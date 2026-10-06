# AI Security Labs

Hands-on labs for security people who learn by doing. Each lab is a small,
self-contained environment you stand up on your own machine to **build a real
AI security problem, break it, and understand it**, not just read about it.

Companion posts: **[blueaisecurity.com](https://blueaisecurity.com)**

> AI is moving faster than the security around it. The only way to keep up is to
> stop reading about the attacks and start running them.

## Labs

| # | Lab | What you learn | Write-up |
|---|-----|----------------|----------|
| 01 | [Prompt Injection](01-prompt-injection) | Trick an LLM chatbot into leaking a secret it was told to protect, and see why input/output filters fail. | [Read](https://blueaisecurity.com/learn-by-doing-ai-security-01-prompt-injection) |
| 02 | [MCP Security](02-mcp-security) | Give the chatbot tools via MCP, then hijack it with tool poisoning and indirect injection. | [Read](https://blueaisecurity.com/learn-by-doing-ai-security-02-mcp) |
| 03 | [Agent Hijacking](03-agent-security) | Trick an agent into reading your inbox and emailing a password to an attacker (the EchoLeak pattern). | [Read](https://blueaisecurity.com/learn-by-doing-ai-security-03-agents) |
| 04 | [Runtime Defense](04-runtime-defense) | Put an AI gateway in front of an email agent, switch on eight checks one at a time, and see which ones stop it from emailing AWS keys to an attacker. | [Read](https://blueaisecurity.com/learn-by-doing-ai-defence-02-gateway-lab) |

Each lab's write-up covers the theory, the architecture, and, where it applies,
the attempts that *didn't* work before the attack landed.

## Requirements

- **Docker Desktop** (free for personal use): https://docs.docker.com/get-docker/
- **git**
- **On Windows:** run Labs 01 to 03 from an Ubuntu terminal in WSL2, not from cmd or
  PowerShell. Lab 04 runs from any of them.
  1. Install WSL2: run `wsl --install` in an admin PowerShell, then restart.
  2. In Docker Desktop, switch on **Settings > Resources > WSL Integration** for Ubuntu.
  3. If `wsl` opens a terminal named `docker-desktop`, that is Docker's own system, not
     Ubuntu. Install Ubuntu with `wsl --install -d Ubuntu`.

Each lab runs local models with Ollama **inside a container**: no API key, no cloud cost.

> **Lab 01: do not install Ollama natively.** A native Ollama starts by itself and takes
> port **11434**, which Lab 01's own Ollama needs. If Lab 01 says `port is already allocated`
> or `Bind for 0.0.0.0:11434 failed`, a native Ollama is running. Quit it (Windows: system tray,
> then Quit, or `taskkill /F /IM ollama.exe`; Linux and WSL: `sudo pkill ollama`) and start
> the lab again. On Windows, also turn off Ollama in **Settings > Apps > Startup**, so it
> doesn't take the port again after every restart.

## Quick start (Lab 01)

```bash
git clone https://github.com/blueaisecurity/ai-security-labs.git
cd ai-security-labs/01-prompt-injection

docker compose up -d --build
docker compose exec ollama ollama pull llama3.2
```

The first command starts both containers. The second downloads the model, about
2 GB, only the first time.

Then open **http://localhost:8000** and try to make the bot reveal its secret.
The full walkthrough is in [`01-prompt-injection/README.md`](01-prompt-injection/README.md).

## Quick start (Lab 02)

```bash
git clone https://github.com/blueaisecurity/ai-security-labs.git
cd ai-security-labs/02-mcp-security

docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:7b
```

Skip the clone if you already have the repo. The first `docker compose` command
starts the three containers. The second downloads the model, about 4.7 GB, only
the first time.

Then open **http://localhost:8000** and try these:

- `What is 2 + 2?`: a harmless baseline, often with no tool call
- `Look up the account status for alice`: tool poisoning
- `Summarize support ticket 42`: indirect injection

It worked when the reply leaks `RX-4417-KENDALL`. The full walkthrough is in
[`02-mcp-security/README.md`](02-mcp-security/README.md).

> Only run one lab at a time, because they all use port 8000. Run `docker compose down`
> in the other lab's folder before starting this one.

## Quick start (Lab 03)

```bash
git clone https://github.com/blueaisecurity/ai-security-labs.git
cd ai-security-labs/03-agent-security

docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:7b
```

Skip the clone if you already have the repo. The first `docker compose` command
starts the three containers. The second downloads the model, about 4.7 GB, only
the first time.

Then open **http://localhost:8000** and ask the most innocent thing you can:

- `Summarize my inbox`: the agent reads the inbox, finds a poisoned email, and
  calls `send_email` to send a password to an attacker, then gives you a normal
  summary.

It worked when the red alarm fires and the trace shows `send_email` sending the
VPN password to `audit@external-vendor.com`. A safe mock catches it, so nothing
is really sent. The full walkthrough is in
[`03-agent-security/README.md`](03-agent-security/README.md).

> Only run one lab at a time, because they all use port 8000. Run
> `docker compose down` in the other lab's folder before starting this one.

## Quick start (Lab 04)

```bash
git clone https://github.com/blueaisecurity/ai-security-labs.git
cd ai-security-labs/04-runtime-defense
docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:3b
docker compose exec ollama ollama pull qwen2.5:7b
```

Skip the clone if you already have the repo. The last two commands download the
two models, about 6.6 GB together, only the first time: qwen2.5:3b runs the
agent, and qwen2.5:7b is the judge. You need about 18 GB of disk and about 8 GB
of memory for Docker. The commands work in PowerShell or cmd on Windows, in WSL, and on macOS and Linux.

Then open **http://localhost:8000**, keep every check off, pick the **blunt**
attack, and ask:

- `Summarize my inbox`: the agent reads the poisoned email and sends the AWS
  keys to an attacker. The gateway passes the traffic and changes nothing.

Now switch the gateway's checks on, one at a time, and see which ones stop it.
LiteLLM's own dashboard runs too, at **http://localhost:4000/ui**: sign in as
`admin` with the password `sk-lab04-dashboard` to see the checks and every
call of the agent's model. The full walkthrough, with what to expect at every step, is in
[`04-runtime-defense/README.md`](04-runtime-defense/README.md).

> Only run one lab at a time, because they all use port 8000. Run
> `docker compose down` in the other lab's folder before starting this one.

## License

MIT. Use it, fork it, teach with it. If you build something on top of it, I want to see it.
