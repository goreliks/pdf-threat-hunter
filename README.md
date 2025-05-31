# PDF Threat Hunter 🕵️‍♂️📄 *(Work‑in‑Progress)*

**PDF Threat Hunter** is an open‑source project aiming to provide multi‑agent
threat‑hunting for PDF files.  
The first milestone – a static‑analysis agent – is **already functional**, though
some features are still being added and refined.

---

## Quick Start

```bash
git clone https://github.com/your‑org/pdf-threat-hunter.git
cd pdf-threat-hunter

python -m venv .venv
source .venv/bin/activate        # Windows → .\.venv\Scripts\activate

pip install -r requirements.txt
pip install -e .

# 1) copy the sample env and add your keys
cp .env.example .env
#    then edit the file or export variables manually:
#    export OPENAI_API_KEY="sk-xxxxxxxx"
#    export LANGSMITH_PROJECT="pdf-threat-hunter"

# 2) analyse a sample file
python scripts/run_static.py samples/hello_world_js.pdf
```

For live step‑by‑step output use:

```bash
python scripts/run_static_stream.py samples/hello_world_js.pdf
```

---

## Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `OPENAI_API_KEY`       | ✔︎ | main LLM backend |
| `ANTHROPIC_API_KEY`    |    | future alternate LLM |
| `LANGSMITH_API_KEY`    |    | optional tracing backend |
| `LANGSMITH_PROJECT`    |    | project name shown in LangSmith |
| `LANGSMITH_TRACING_V2` |    | set to `true` to enable tracing |

Create a `.env` from the provided **.env.example** or export variables in your shell.

---

## How It Works (Current Stage)

1. **SafeShell** executes only a strict allow‑list of command‑line tools inside
   a sandbox.
2. A **planning LLM** reasons about each tool's output and decides what to ask
   for next.
3. The framework is orchestrated with **LangGraph**, enabling a plan → act → reflect loop.
4. A detailed final report plus the full internal state are stored in
   `outputs/`.

---

## Directory Overview

```
analysis_tools/            # vendored command‑line helpers
src/
 └─ pdf_threat_hunter/
     ├─ agents/
     │   └─ static_pdf/    # current working agent
     └─ tools/             # sandbox + future API wrappers
scripts/                   # CLI entry points
tests/                     # pytest suite
```

---

## Roadmap

- [x] Static analysis agent   *(initial version)*
- [ ] Vision agent for rendered‑page heuristics
- [ ] External threat‑intel enrichment
- [ ] Multi‑agent orchestrator
- [ ] Docker distribution & simple web UI

---

## Contributing

We welcome issues, pull requests and feature ideas.  
Please run the linter and test suite before submitting a PR.

---

## License

MIT © 2025 Gorelik
