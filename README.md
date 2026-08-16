# ControlTrace AI

A cybersecurity compliance and risk management platform. FastAPI backend, SQLite by
default (swap to PostgreSQL with `DATABASE_URL`), server-rendered UI with session
login and role-based access control.

## What's included

- **26 compliance frameworks** (NIST CSF 2.0, ISO/IEC 27001, CIS Controls v8, NIST
  SP 800-53, PCI DSS, SOC 2, FedRAMP, FISMA, CMMC, CJIS, ITAR, HIPAA, HITECH,
  21 CFR Part 11, SOX, GLBA, FFIEC, GDPR, ISO 27017/27018/22301, NERC CIP, HITRUST
  CSF, COBIT, SWIFT CSP, SOC 1) with 400+ underlying controls
- **Executive Dashboard** — live compliance score, per-framework coverage, top
  risks, recent findings
- **Risk Register** — likelihood × impact scoring, treatment plans, status tracking
- **Evidence Repository** — CSV upload, SHA-256 hashing, automatic control
  evaluation and finding creation
- **Policy Manager** — draft/review/approve workflow, linked to frameworks
- **Document Library** — general-purpose file storage with categories and notes
- **Workflow & Tasks** — kanban board for remediation and audit prep work
- **Vendor Management** — third-party risk tiering
- **Notifications** — in-app alerts generated from uploads, risks, and findings
- **AI Assistant** — answers questions from your live compliance data; uses the
  Anthropic API for open-ended reasoning if `ANTHROPIC_API_KEY` is set, otherwise
  falls back to a built-in rules-based insights engine (no external dependency
  required to use it)
- **Audit Log** — every action recorded, org-scoped
- **User Management & RBAC** — Administrator / Auditor / Viewer roles
- **Reports** — CSV export of framework-level compliance scores
- **Framework Mapping**, **Control Library**, **Integrations catalog**

Login uses server-side sessions (httponly cookie) with bcrypt-hashed passwords.
A legacy JSON API (`/auth/login`, `/control-results`, `/dashboard/summary`, …)
is still available and documented at `/docs`.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- App: http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs

On first run the app auto-creates the SQLite database and seeds:
- 1 demo organization
- 3 demo users (see below)
- All 26 frameworks and their controls
- A handful of sample risks, policies, vendors, and a welcome notification

### Demo accounts

| Role          | Email                        | Password     |
|---------------|-------------------------------|--------------|
| Administrator | admin@controltrace.local      | Mente1122    |
| Auditor       | auditor@controltrace.local    | Auditor123   |
| Viewer        | viewer@controltrace.local     | Viewer123    |

Change these before using this anywhere beyond a local demo.

## Sample evidence file

Upload `docs/sample_mfa.csv` from the Evidence Repository page to see a control
evaluation and finding get created automatically. Expected format:

```csv
User,MFA Enabled,Is Admin
admin1@company.com,Yes,Yes
admin2@company.com,No,Yes
user1@company.com,Yes,No
```

Accepted truthy values: `Yes`, `True`, `1`, `Y`.

## AI Assistant (optional live LLM)

By default the AI Assistant answers from a built-in insights engine that reads
your live risks, findings, and compliance scores — no setup required. To enable
full conversational answers powered by Claude:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn app.main:app --reload
```

## PostgreSQL

```bash
export DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/controltrace
pip install "psycopg[binary]"
```

## Project structure

```
app/
  main.py        FastAPI routes (pages + legacy JSON API)
  models.py      SQLAlchemy models
  services.py    Business logic: evidence parsing, framework/control seed data,
                 compliance scoring, audit logging, AI assistant
  auth.py        Password hashing, session tokens, RBAC role constants
  database.py    Engine/session setup (SQLite by default)
  templates/     Jinja2 templates (server-rendered UI)
  static/        CSS
docs/
  sample_mfa.csv Example evidence file
```

## Honest scope note

This is a working single-tenant MVP suitable for a demo, an internal pilot, or a
foundation to build on — not a hardened, audited, multi-tenant production SaaS.
Before using it with real customer data: put it behind HTTPS, move off the dev
`SECRET_KEY` in `app/auth.py`, add rate limiting on `/login`, add CSRF protection
on the HTML forms, and move to PostgreSQL.
