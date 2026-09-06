# AI Security Labs

Hands-on labs for security people who learn by doing. Each lab is a small,
self-contained environment you stand up on your own machine to **build a real
AI security problem, break it, and understand it** — not just read about it.

Companion posts: **[blueaisecurity.com](https://blueaisecurity.com)**

> AI is moving faster than the security around it. The only way to keep up is to
> stop reading about the attacks and start running them.

## Labs

| # | Lab | What you learn |
|---|-----|----------------|
| 01 | [Prompt Injection](01-prompt-injection) | Trick an LLM chatbot into leaking a secret it was told to protect, and see why input/output filters fail. |
| 02 | MCP Security *(coming soon)* | Attack the connection layer between an agent and its tools. |
| 03 | Agent Security *(coming soon)* | Hijack an agent's reasoning loop into taking actions it should not. |

## Requirements

- **Docker Desktop** (free for personal use). On Windows, enable WSL integration.
- That's it. Each lab runs a local model via Ollama **inside the container** — no
  API key, no cloud cost. Do not install Ollama natively; it will fight for the port.

## Quick start (Lab 01)

```bash
git clone https://github.com/blueaisecurity/ai-security-labs.git
cd ai-security-labs/01-prompt-injection

docker compose up -d --build                     # start both containers
docker compose exec ollama ollama pull llama3.2  # download the model (first run, ~2 GB)
```

Then open **http://localhost:8000** and try to make the bot reveal its secret.
Full walkthrough is in [`01-prompt-injection/README.md`](01-prompt-injection/README.md).

## License

MIT. Use it, fork it, teach with it. If you build something on top of it, I want to see it.
