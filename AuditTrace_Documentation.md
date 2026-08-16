# AuditTrace AI — Full Operations Guide
**Version 1.0 | NetworkCGI | Confidential**

---

## TABLE OF CONTENTS
1. Project Overview
2. Project File Structure
3. How to Run the Server (Daily Use)
4. How to Stop the Server
5. How to Update Your Code (Windows → GitHub → Ubuntu)
6. GitHub Connection Guide
7. Troubleshooting Common Errors

---

## 1. PROJECT OVERVIEW

AuditTrace AI is a cybersecurity compliance platform built with:
- **Backend:** FastAPI (Python)
- **Database:** SQLite (local)
- **Server:** Uvicorn
- **Hosting:** Ubuntu VM on Hyper-V (home server)
- **Code Repository:** GitHub (NetworkCGI/AuditTrace-AI-MVP)

**Access URLs (when server is running):**
- Dashboard: http://127.0.0.1:8000
- Frameworks: http://127.0.0.1:8000/frameworks
- Controls: http://127.0.0.1:8000/controls
- History: http://127.0.0.1:8000/history
- Reports: http://127.0.0.1:8000/reports
- API Docs: http://127.0.0.1:8000/docs

---

## 2. PROJECT FILE STRUCTURE

```
AuditTrace-AI-MVP/
├── app/
│   ├── main.py          ← Routes and startup logic
│   ├── models.py        ← Database table definitions
│   ├── services.py      ← Business logic and seed data
│   ├── database.py      ← Database connection
│   ├── auth.py          ← Authentication helpers
│   ├── schemas.py       ← API data shapes
│   ├── static/
│   │   └── logo.png     ← App logo
│   ├── templates/
│   │   ├── dashboard.html
│   │   ├── frameworks.html
│   │   ├── controls.html
│   │   └── history.html
│   └── uploads/         ← Uploaded CSV evidence files
├── migrate_db.py        ← One-time database migration script
├── requirements.txt     ← Python package dependencies
├── audittrace.db        ← SQLite database file
└── README.md
```

---

## 3. HOW TO RUN THE SERVER (DAILY USE)

### On Ubuntu (Hyper-V VM)

**Step 1 — Open your Ubuntu VM**
- Open Hyper-V Manager on Windows
- Double click your Ubuntu VM to open it
- Log in with your username and password

**Step 2 — Open Terminal**
- Right click on the desktop
- Click "Open Terminal"

**Step 3 — Navigate to project folder**
```bash
cd ~/AuditTrace-AI-MVP
```

**Step 4 — Activate virtual environment**
```bash
source .venv/bin/activate
```
You will see `(.venv)` appear at the start of the line.

**Step 5 — Start the server**
```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Step 6 — Confirm it is running**
You should see:
```
INFO: Uvicorn running on http://0.0.0.0:8000
INFO: Application startup complete.
```

**Step 7 — Open the app in Firefox**
```
http://127.0.0.1:8000
```

---

### Access from Other Computers on Your Network

**Find your Ubuntu IP address:**
Open a second terminal and run:
```bash
ip a
```
Look for a number like `192.168.x.x`

Then from any computer on your home network open a browser and go to:
```
http://192.168.x.x:8000
```

---

## 4. HOW TO STOP THE SERVER

In the terminal where the server is running:
```
Press CTRL + C
```

---

## 5. HOW TO UPDATE YOUR CODE

### Workflow Overview
```
Edit code on Windows
       ↓
Push to GitHub (Git Bash on Windows)
       ↓
Pull on Ubuntu
       ↓
Restart server
```

---

### PART A — Edit and Push from Windows

**Step 1 — Make your code changes on Windows**
Edit files in: `D:\audittrace\audittrace_mvp\`

**Step 2 — Open Git Bash on Windows**
- Press Windows key
- Type `Git Bash`
- Click to open

**Step 3 — Navigate to project**
```bash
cd /d/audittrace/audittrace_mvp
```

**Step 4 — Add changed files**
```bash
git add .
```

**Step 5 — Commit with a message**
```bash
git commit -m "describe what you changed"
```

**Step 6 — Push to GitHub**
```bash
git push origin main
```

**Step 7 — Sign in if asked**
A browser window will open — sign in with your GitHub account.

---

### PART B — Pull and Restart on Ubuntu

**Step 1 — Open Terminal on Ubuntu**

**Step 2 — Stop the server if running**
```
CTRL + C
```

**Step 3 — Navigate to project**
```bash
cd ~/AuditTrace-AI-MVP
```

**Step 4 — Activate virtual environment**
```bash
source .venv/bin/activate
```

**Step 5 — Pull latest code from GitHub**
```bash
git pull origin main
```

**Step 6 — Run migration if models changed**
```bash
python3 migrate_db.py
```

**Step 7 — Restart server**
```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 6. GITHUB CONNECTION GUIDE

### Your GitHub Details
- **Account:** https://github.com/NetworkCGI
- **Repository:** https://github.com/NetworkCGI/AuditTrace-AI-MVP
- **Branch:** main

---

### First Time Setup on a New Computer (Windows)

**Step 1 — Install Git**
Download from: https://git-scm.com/download/win
Install with all default settings.

**Step 2 — Open Git Bash**

**Step 3 — Configure your identity**
```bash
git config --global user.name "NetworkCGI"
git config --global user.email "your@email.com"
```

**Step 4 — Clone the repository**
```bash
cd /d
git clone https://github.com/NetworkCGI/AuditTrace-AI-MVP.git
```

---

### First Time Setup on a New Ubuntu Machine

**Step 1 — Install Git**
```bash
sudo apt update
sudo apt install git -y
```

**Step 2 — Configure your identity**
```bash
git config --global user.name "NetworkCGI"
git config --global user.email "your@email.com"
```

**Step 3 — Clone the repository**
```bash
cd ~
git clone https://github.com/NetworkCGI/AuditTrace-AI-MVP.git
```

**Step 4 — Go into the folder**
```bash
cd AuditTrace-AI-MVP
```

**Step 5 — Create virtual environment**
```bash
python3 -m venv .venv
```

**Step 6 — Activate it**
```bash
source .venv/bin/activate
```

**Step 7 — Install packages**
```bash
pip install -r requirements.txt
```

**Step 8 — Run migration**
```bash
python3 migrate_db.py
```

**Step 9 — Start server**
```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

### How to Create a Personal Access Token (GitHub Password)

GitHub does not accept your regular password for Git commands.
You need a Personal Access Token.

**Step 1** — Go to: https://github.com/settings/tokens

**Step 2** — Click "Generate new token (classic)"

**Step 3** — Give it a name: `audittrace`

**Step 4** — Check the "repo" checkbox

**Step 5** — Scroll down and click "Generate token"

**Step 6** — COPY the token immediately — you only see it once

**Step 7** — Use this token as your password when Git asks

---

## 7. TROUBLESHOOTING COMMON ERRORS

---

### Error: `command 'python' not found`
**Fix:** Use `python3` instead of `python`
```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

### Error: `TemplateNotFound: controls.html`
**Cause:** File is named `Controls.html` (capital C) — Linux is case sensitive
**Fix:**
```bash
mv ~/AuditTrace-AI-MVP/app/templates/Controls.html ~/AuditTrace-AI-MVP/app/templates/controls.html
```

---

### Error: `ModuleNotFoundError`
**Cause:** Virtual environment not activated
**Fix:**
```bash
source .venv/bin/activate
```

---

### Error: `Address already in use`
**Cause:** Server is already running on port 8000
**Fix:** Find and kill it:
```bash
fuser -k 8000/tcp
```
Then start again.

---

### Error: `git push` — Repository not found
**Fix:** Check remote URL is correct:
```bash
git remote -v
```
If wrong, reset it:
```bash
git remote remove origin
git remote add origin https://github.com/NetworkCGI/AuditTrace-AI-MVP.git
git push origin main
```

---

### Error: Internal Server Error on /frameworks or /controls
**Cause:** Database not seeded or migration not run
**Fix:**
```bash
python3 migrate_db.py
```
Then restart server.

---

### Frameworks and Controls not showing
**Cause:** Old services.py without seed data
**Fix:** Pull latest code and restart:
```bash
git pull origin main
python3 migrate_db.py
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## QUICK REFERENCE CARD

| Task | Command |
|---|---|
| Start server | `python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload` |
| Stop server | `CTRL + C` |
| Activate venv | `source .venv/bin/activate` |
| Go to project | `cd ~/AuditTrace-AI-MVP` |
| Pull updates | `git pull origin main` |
| Run migration | `python3 migrate_db.py` |
| Push changes | `git add . && git commit -m "message" && git push origin main` |
| Check IP | `ip a` |
| Kill port 8000 | `fuser -k 8000/tcp` |

---

*AuditTrace AI | NetworkCGI | Internal Documentation*
