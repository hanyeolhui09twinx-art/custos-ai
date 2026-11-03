"""Run an OpenAI Agent whose registered function tools are mediated by Custos.

Requires:
  pip install -r requirements-agents.txt
  CUSTOS_AGENT_TOKEN=<token for research_agent>
  OPENAI_API_KEY=<development key>

The example uses the repository's mock execution adapter. It does not connect
to an actual database or email service.
"""

from __future__ import annotations

import asyncio
import os

from agents import Runner

from integrations.custos_client import CustosClient
from integrations.openai_agents_sdk import create_custos_agent


async def main() -> None:
    token = os.environ.get("CUSTOS_AGENT_TOKEN", "")
    if not token:
        raise SystemExit("Set CUSTOS_AGENT_TOKEN for the configured research_agent.")
    client = CustosClient(
        agent_token=token,
        base_url=os.environ.get("CUSTOS_API_URL", "http://127.0.0.1:8765"),
    )
    agent = create_custos_agent(client)
    result = await Runner.run(
        agent,
        "Use the research database tool to look up the current market research summary. "
        "Report the Custos decision and whether the operation was simulated.",
    )
    print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
