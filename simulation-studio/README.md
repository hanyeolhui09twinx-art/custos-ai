# Custos AI Simulation Studio

## Browser Simulation Studio

Open index.html in a modern browser, or use the hosted GitHub Pages site. The browser simulation is self-contained and does not need Python or a local server.

- Korean / English interface
- 13 predefined scenarios
- Policy, authority, human-approval, sequential, and Multi-Agent simulations
- Pause/resume, browser-local history, and trace/report export

## Local API Console

The Local API Console is a separate browser page linked from the Studio sidebar:

- Open the hosted GitHub Pages site and select **Local API Console**.
- Start the Python API on your own computer using the instructions in the repository root README.
- Enter the local agent and reviewer tokens directly into the console. They are held in page memory only and are not written to localStorage.
- Test the connection, submit a request, review pending approvals, and execute an approved request.

The console talks to http://127.0.0.1:8765 on the user's own computer. The API allows browser CORS only from the official Custos GitHub Pages origin. The browser may ask the user to grant **Loopback network** access to the GitHub Pages site; this permission is controlled by the browser. A denied permission or blocked local request will prevent the console from connecting.

## Important boundaries

- The regular Studio at index.html remains a browser-only simulation. It does not call real agents or production services.
- The Local API Console connects to the local Python API, but the backend still uses a mock execution adapter. The read_database and send_email actions do not access a real database or send messages.
- The local API binds to loopback only. Do not expose it to a LAN or the public internet.
- The local API has no TLS or production credential lifecycle. Do not connect valuable tools or use production secrets.
- Tokens are not deliberately persisted by the console, but browser extensions, compromised devices, screenshots, and malicious local software remain outside this protection.

See the root README for local API setup and API routes, and docs/THREAT_MODEL.md for assumptions and limitations.
