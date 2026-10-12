"""Durable state: restored pending requests are re-verified, rejection is authenticated,
the anchor only moves forward."""
from __future__ import annotations

import json
import threading

import pytest

from custos.audit import FileAnchor
from custos.bootstrap import ManualClock, build_world
from custos.control_plane import ControlError, sign_rejection
from custos.crypto import generate_keypair

EMAIL = {"to": "x@company.local", "subject": "s", "body": "b"}


def park(w):
    r = w.request(action="send_email", resource="company_email", params=EMAIL)
    assert w.gateway.submit(r).status == "PENDING_APPROVAL"
    return r, w.gateway.describe_pending(r.request_id)


def test_restore_reloads_valid_pending_requests(tmp_path):
    w = build_world(tmp_path, clock=ManualClock())
    r, view = park(w)
    w.gateway.drop_pending(r.request_id)  # simulate a restart: memory is gone, the database remains
    assert w.gateway.describe_pending(r.request_id) is None
    assert w.gateway.restore_pending() == 1
    assert w.gateway.describe_pending(r.request_id)["digest"] == view["digest"]
    assert w.gateway.execute_approved(r.request_id, w.approve(r.request_id)).executed


def test_restore_ignores_bodies_that_do_not_match_their_recorded_digest(tmp_path):
    w = build_world(tmp_path, clock=ManualClock())
    r, view = park(w)
    w.gateway.drop_pending(r.request_id)
    body = json.loads(w.state._one("SELECT body FROM requests WHERE request_id=?", (r.request_id,))[0])
    body["parameters"] = {**EMAIL, "to": "evil@company.local"}  # someone edits the stored request
    w.state._exec("UPDATE requests SET body=? WHERE request_id=?", (json.dumps(body), r.request_id))
    assert w.gateway.restore_pending() == 0 and w.gateway.describe_pending(r.request_id) is None
    w.state._exec("UPDATE requests SET body='{not json' WHERE request_id=?", (r.request_id,))
    assert w.gateway.restore_pending() == 0  # corrupt storage fails closed, no exception


def test_restore_ignores_expired_and_already_decided_requests(tmp_path):
    from custos.control_plane import PENDING_TTL
    w = build_world(tmp_path, clock=ManualClock())
    a, _ = park(w)
    b, _ = park(w)
    w.state.transition(b.request_id, "PENDING_APPROVAL", "DENIED")
    w.gateway.drop_pending(a.request_id), w.gateway.drop_pending(b.request_id)
    w.clock.advance(PENDING_TTL + 1)
    assert w.gateway.restore_pending() == 0
    c, _ = park(w)
    w.gateway.drop_pending(c.request_id)
    assert w.gateway.restore_pending() == 1  # only the fresh one


def test_rejection_requires_the_approvers_signature_over_this_exact_request(tmp_path):
    w = build_world(tmp_path, clock=ManualClock())
    r, view = park(w)
    other, other_view = park(w)
    good = sign_rejection(w.approver_key, r.request_id, view["digest"])
    for who, sig, rid in (("alice_ops", "00" * 64, r.request_id),
                          ("mallory", good, r.request_id),  # unknown approver
                          ("alice_ops", sign_rejection(generate_keypair()[0], r.request_id, view["digest"]), r.request_id),
                          ("alice_ops", good, other.request_id),  # signature for a different request
                          ("alice_ops", sign_rejection(w.approver_key, r.request_id, "0" * 64), r.request_id)):
        with pytest.raises(ControlError):
            w.control.reject(rid, who, sig)
    assert w.state.get_request(r.request_id)[0] == "PENDING_APPROVAL"
    w.control.reject(r.request_id, "alice_ops", good)
    assert w.state.get_request(r.request_id)[0] == "DENIED"
    with pytest.raises(ControlError):
        w.control.reject(r.request_id, "alice_ops", good)  # already decided
    assert w.executor.executions == 0


def test_a_rejected_request_cannot_be_approved_afterwards(tmp_path):
    w = build_world(tmp_path, clock=ManualClock())
    r, view = park(w)
    w.control.reject(r.request_id, "alice_ops", sign_rejection(w.approver_key, r.request_id, view["digest"]))
    with pytest.raises(ControlError):
        w.approve(r.request_id)
    assert not w.gateway.execute_approved(r.request_id, "anything").executed


def test_anchor_only_moves_forward_and_is_safe_under_concurrency(tmp_path):
    a = FileAnchor(tmp_path / "anchor.json")
    assert a.head is None
    a.publish(5, "h5")
    a.publish(3, "h3")  # an older head must never overwrite a newer one
    a.publish(5, "other")
    assert a.head == (5, "h5")
    ts = [threading.Thread(target=lambda i=i: a.publish(i, f"h{i}")) for i in range(6, 40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert a.head == (39, "h39")
    assert FileAnchor(tmp_path / "anchor.json").head == (39, "h39")  # survives a new process
    (tmp_path / "anchor.json").write_text("garbage")
    assert a.head is None  # unreadable anchor is "no anchor", never a crash
