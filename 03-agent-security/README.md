# Lab 03 — Agent Hijacking (EchoLeak pattern)

Lab #2 tricked an AI into *saying* a secret. This lab tricks an agent into *doing*
something: it reads your inbox, finds a password, and sends it to an attacker,
all from one poisoned email. It is a small, local recreation of **EchoLeak**
(CVE-2025-32711), the first documented case of prompt injection weaponized for
real data theft in a production AI system.

Full write-up: **[blueaisecurity.com](https://blueaisecurity.com)**

```
Browser (:8000)  ->  Email agent  ->  Ollama (:11434)   the local model
                                   ->  MCP server (:9000) inbox + send_email
```

Three containers, fully local, no API key. Everything is simulated and safe:
the inbox is fake and `send_email` does not send anything, it only logs the
attempt so you can watch the agent try.

## Requirements

- **Docker Desktop** (free for personal use) — https://docs.docker.com/get-docker/
- On **Windows**: run from your **Ubuntu (WSL) terminal**, not CMD, with WSL
  integration enabled in Docker Desktop.
- No API key. Model (via Ollama) and MCP server both run in containers.

## Run it

```bash
docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:7b   # first run, ~4.7 GB
```

Then open **http://localhost:8000** and ask the most innocent thing you can:

```
Summarize my inbox
```

Watch the activity feed. The agent reads the inbox, hits a poisoned email that
tells it to forward the password, calls `send_email` to ship it to the attacker
(`audit@external-vendor.com`), and then hands you a normal-looking summary. The
red alarm flags the malicious action; the safe mock logs the exfiltration
attempt instead of actually sending it.

## The tools

The MCP server exposes two tools:

- `read_emails` — returns a small fake inbox. One email contains a VPN password.
  One email (from `partner@external-vendor.com`) hides an instruction.
- `send_email` — the agent's "external reach." A **safe mock**: it does not send
  anything, it logs the attempt loudly.

## Why this works: three powers

The agent is exploitable because it has all three at once (Simon Willison's
"lethal trifecta"):

1. **private data** — it can read your inbox
2. **untrusted input** — emails come from anyone
3. **external reach** — it can send email

Remove any one and the attack has nowhere to go.

## Note on reliability

The attack is iterative. A vague, polite poisoned email gets ignored. A firm
"required system task" gets the model to leak the password and announce it will
send it, but a small local model may still not complete the tool call. Telling
it to *actually invoke the tool, not describe it* is what makes `send_email`
fire. The manipulation is the point; the model's capability decides how far the
action goes.

## Files

```
03-agent-security/
├── docker-compose.yml           # ollama + mcp-server + email agent
├── mcp-server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── vuln_mcp_server.py       # the fake inbox + poisoned email + send_email
└── chatbot/
    ├── Dockerfile
    ├── requirements.txt
    └── app/main.py              # the agent loop + browser UI
```

## Reset

```bash
docker compose down       # stop
docker compose down -v    # stop and delete the downloaded model
```
