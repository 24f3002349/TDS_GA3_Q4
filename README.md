# GA5 Observable Incident Triage agent

Public HTTPS incident agent: one model call diagnoses the incident and plans the minimal diagnostics and one effect;
a receipt-driven state machine handles 503 retries, timeouts, approvals and the terminal state; the OTLP trace is
built only from stored dispatches and receipts.

| File | Layer |
|---|---|
| `app.py` | HTTP: validation, idempotent replay, 409 conflicts, per-run locks, redaction of every response |
| `planner.py` | The only model caller: prompt, provider fallback, plan validation against the tool schemas, plan cache |
| `engine.py` | State machine: dispatches, receipts, retries, approval gate, terminal state. Never calls a model |
| `otlp.py` | OTLP/JSON trace from stored state. Exports no transcript, prompt, arguments or sensitive values |
| `store.py` | SQLite. State is committed before the response is sent |
| `test_local.py` | Local contract test with synthetic incidents (`python test_local.py http://127.0.0.1:8000`) |

## Endpoints

* `POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`, `GET /v2/incidents/{runId}`
* `GET /healthz` shows each model's last outcome (never the key).

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `GEMINI_API_KEY` | (required) | Free Google AI Studio key (https://aistudio.google.com/apikey). Comma-separate several keys to spread free-tier quota |
| `LLM_MODEL` | `gemini-3.6-flash,gemini-3-flash-preview,gemini-3.5-flash` | Free models, rotated per call (each has its own free quota) |
| `LLM_LAST_MODELS` | `gemini-3.5-flash-lite` | Used only when the models above are rate-limited |
| `FALLBACK_API_KEY` / `FALLBACK_BASE_URL` / `FALLBACK_MODEL` | unset | Optional second provider (any OpenAI-compatible endpoint) |
| `LLM_CALL_TIMEOUT_S` | 8 | Per-model timeout before trying the next one |
| `PLAN_BUDGET_S` | 14 | Total planning budget (the grader allows 18 s per request) |
| `DB_PATH` | `incidents.sqlite3` | SQLite file (`/tmp/incidents.sqlite3` on Render) |
| `KEEPALIVE_URL` | `RENDER_EXTERNAL_URL` | Pinged every 10 min so the free instance does not sleep |

Tests: `python test_engine.py` (state machine and trace rules, no model needed) and
`python test_local.py <base-url>` (full HTTP contract with synthetic incidents; uses the model).

Run locally: `pip install -r requirements.txt && python app.py` (reads `.env`, listens on `PORT`, default 8000).
