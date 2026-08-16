from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import csv
import io

from .database import Base, engine, get_db
from . import models, schemas, services
from .services import (
    save_upload, parse_mfa_csv, seed_defaults, evaluate_mfa_control,
    seed_frameworks_and_controls, seed_sample_workspace_data,
    log_action, notify, compliance_by_framework, ai_assistant_reply,
)
from .auth import (
    verify_password, create_access_token, hash_password,
    new_session_token, ADMIN_ROLES, EDITOR_ROLES, ROLE_LABELS,
)


app = FastAPI(title="ControlTrace AI")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

Base.metadata.create_all(bind=engine)

SESSION_COOKIE = "ct_session"
SESSION_HOURS = 12


@app.on_event("startup")
def startup_seed():
    db = next(get_db())
    try:
        seed_defaults(db)
        seed_frameworks_and_controls(db)
        seed_sample_workspace_data(db)
    finally:
        db.close()


# -- Session / auth helpers --------------------------------------------------

def get_current_user(request: Request, db: Session):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = db.query(models.UserSession).filter(models.UserSession.token == token).first()
    if not session or session.expires_at < datetime.utcnow():
        return None
    user = db.query(models.User).filter(models.User.id == session.user_id).first()
    return user


def require_login(request: Request, db: Session):
    """Returns the user, or a RedirectResponse to /login if not authenticated.
    Callers should check `isinstance(result, RedirectResponse)`."""
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url=f"/login?next={request.url.path}", status_code=303)
    return user


def base_ctx(request: Request, user, db: Session, **extra):
    unread = 0
    if user:
        unread = db.query(models.Notification).filter(
            models.Notification.organization_id == user.organization_id,
            models.Notification.is_read == False,  # noqa: E712
        ).count()
    ctx = {
        "request": request, "user": user, "role_label": ROLE_LABELS.get(getattr(user, "role", None), ""),
        "can_edit": getattr(user, "role", None) in EDITOR_ROLES,
        "is_admin": getattr(user, "role", None) in ADMIN_ROLES,
        "unread_notifications": unread,
    }
    ctx.update(extra)
    return ctx


# -- Auth pages ---------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "next": next})


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, email: str = Form(...), password: str = Form(...),
                  next: str = Form("/"), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email.strip().lower()).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid email or password.", "next": next},
            status_code=401,
        )
    token = new_session_token()
    db.add(models.UserSession(
        user_id=user.id, token=token,
        expires_at=datetime.utcnow() + timedelta(hours=SESSION_HOURS),
    ))
    db.commit()
    log_action(db, user.organization_id, user.email, "login", "User signed in")
    resp = RedirectResponse(url=next or "/", status_code=303)
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, max_age=SESSION_HOURS * 3600)
    return resp


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        session = db.query(models.UserSession).filter(models.UserSession.token == token).first()
        if session:
            db.delete(session)
            db.commit()
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# -- Executive dashboard -------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user

    org = db.query(models.Organization).filter(models.Organization.id == user.organization_id).first()
    latest_result = db.query(models.ControlResult).filter(
        models.ControlResult.organization_id == user.organization_id
    ).order_by(models.ControlResult.evaluated_at.desc()).first()
    findings = db.query(models.Finding).filter(
        models.Finding.organization_id == user.organization_id
    ).order_by(models.Finding.created_at.desc()).limit(8).all()

    passed_controls = db.query(models.ControlResult).filter(
        models.ControlResult.organization_id == user.organization_id, models.ControlResult.status == "pass"
    ).count()
    failed_controls = db.query(models.ControlResult).filter(
        models.ControlResult.organization_id == user.organization_id, models.ControlResult.status == "fail"
    ).count()
    total_results = passed_controls + failed_controls
    compliance_score = round((passed_controls / total_results) * 100, 2) if total_results else 0.0

    fw_scores = compliance_by_framework(db, user.organization_id)

    open_risks = db.query(models.Risk).filter(
        models.Risk.organization_id == user.organization_id, models.Risk.status == "open"
    ).all()
    top_risks = sorted(open_risks, key=lambda r: r.score, reverse=True)[:5]

    open_tasks = db.query(models.WorkflowTask).filter(
        models.WorkflowTask.organization_id == user.organization_id, models.WorkflowTask.stage != "done"
    ).count()

    total_frameworks = db.query(models.Framework).count()
    total_controls = db.query(models.Control).count()

    summary = {
        "organization": org.name if org else "Demo Organization",
        "compliance_score": compliance_score,
        "passed_controls": passed_controls,
        "failed_controls": failed_controls,
        "open_findings": db.query(models.Finding).filter(
            models.Finding.organization_id == user.organization_id, models.Finding.status == "open"
        ).count(),
        "open_risks": len(open_risks),
        "open_tasks": open_tasks,
        "total_frameworks": total_frameworks,
        "total_controls": total_controls,
        "latest_result_summary": latest_result.result_summary if latest_result else "No evaluation yet.",
    }

    return templates.TemplateResponse("dashboard.html", base_ctx(
        request, user, db, summary=summary, findings=findings,
        fw_scores=fw_scores, top_risks=top_risks, active="dashboard",
    ))


# -- Legacy JSON API (kept for /docs) ------------------------------------------

@app.post("/auth/login", response_model=schemas.LoginResponse)
def api_login(payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user.id)
    return schemas.LoginResponse(access_token=token)


@app.get("/control-results", response_model=list[schemas.ControlResultOut])
def get_control_results(db: Session = Depends(get_db)):
    results = db.query(models.ControlResult).order_by(models.ControlResult.evaluated_at.desc()).all()
    return [schemas.ControlResultOut(id=r.id, status=r.status, score=float(r.score),
                                      result_summary=r.result_summary) for r in results]


@app.get("/findings", response_model=None)
def get_findings(request: Request, db: Session = Depends(get_db)):
    accept = request.headers.get("accept", "")
    findings = db.query(models.Finding).order_by(models.Finding.created_at.desc()).all()
    if "text/html" in accept:
        user = require_login(request, db)
        if isinstance(user, RedirectResponse):
            return user
        return templates.TemplateResponse("findings.html", base_ctx(
            request, user, db, findings=findings, active="findings"))
    return [schemas.FindingOut(id=f.id, title=f.title, description=f.description,
                                severity=f.severity, status=f.status) for f in findings]


@app.post("/findings/{finding_id}/close")
def close_finding(finding_id: str, request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if finding:
        finding.status = "closed"
        db.commit()
        log_action(db, user.organization_id, user.email, "finding.close", finding.title)
    return RedirectResponse(url="/findings", status_code=303)


@app.get("/dashboard/summary", response_model=schemas.DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    latest_result = db.query(models.ControlResult).order_by(models.ControlResult.evaluated_at.desc()).first()
    passed_controls = db.query(models.ControlResult).filter(models.ControlResult.status == "pass").count()
    failed_controls = db.query(models.ControlResult).filter(models.ControlResult.status == "fail").count()
    total_results = passed_controls + failed_controls
    compliance_score = round((passed_controls / total_results) * 100, 2) if total_results else 0.0
    open_findings = db.query(models.Finding).filter(models.Finding.status == "open").count()
    return schemas.DashboardSummary(
        compliance_score=compliance_score, passed_controls=passed_controls,
        failed_controls=failed_controls, open_findings=open_findings,
        latest_result_summary=latest_result.result_summary if latest_result else None,
    )


# -- Frameworks / Controls / Framework Mapping ---------------------------------

@app.get("/frameworks", response_class=HTMLResponse)
def frameworks_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    frameworks = db.query(models.Framework).order_by(models.Framework.name).all()
    return templates.TemplateResponse("frameworks.html", base_ctx(
        request, user, db, frameworks=frameworks, active="frameworks"))


@app.get("/controls", response_class=HTMLResponse)
def controls_page(request: Request, db: Session = Depends(get_db), framework_id: str | None = None):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    query = db.query(models.Control)
    if framework_id:
        query = query.filter(models.Control.framework_id == framework_id)
    controls = query.order_by(models.Control.control_code).limit(500).all()
    frameworks = db.query(models.Framework).order_by(models.Framework.name).all()
    return templates.TemplateResponse("controls.html", base_ctx(
        request, user, db, controls=controls, frameworks=frameworks,
        selected_framework_id=framework_id, active="controls"))


@app.get("/framework-mapping", response_class=HTMLResponse)
def framework_mapping_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    fw_scores = compliance_by_framework(db, user.organization_id)
    return templates.TemplateResponse("framework_mapping.html", base_ctx(
        request, user, db, fw_scores=fw_scores, active="framework-mapping"))


# -- Evidence Repository / Upload / History ------------------------------------

@app.get("/evidence", response_class=HTMLResponse)
def evidence_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    items = db.query(models.EvidenceItem).filter(
        models.EvidenceItem.organization_id == user.organization_id
    ).order_by(models.EvidenceItem.collected_at.desc()).all()
    files_by_id = {f.id: f for f in db.query(models.EvidenceFile).all()}
    return templates.TemplateResponse("evidence.html", base_ctx(
        request, user, db, items=items, files_by_id=files_by_id, active="evidence"))


@app.post("/evidence/upload", response_model=None)
async def upload_and_evaluate(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    accept = request.headers.get("accept", "")
    user = get_current_user(request, db)
    org_id = user.organization_id if user else db.query(models.Organization).first().id

    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=500, detail="Organization not initialized")

    file_bytes = await file.read()
    path, digest = save_upload(file_bytes, file.filename)

    evidence_file = models.EvidenceFile(
        organization_id=org.id, file_name=file.filename, file_path=path, file_hash_sha256=digest,
    )
    db.add(evidence_file)
    db.flush()

    evidence_item = models.EvidenceItem(
        organization_id=org.id, evidence_file_id=evidence_file.id, evidence_type="mfa_status_csv",
    )
    db.add(evidence_item)
    db.flush()

    try:
        parsed_rows = parse_mfa_csv(path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    for row in parsed_rows:
        db.add(models.EvidenceNormalizedRecord(
            evidence_item_id=evidence_item.id, subject_identifier=row["subject_identifier"],
            mfa_enabled=row["mfa_enabled"], is_admin=row["is_admin"],
        ))
    db.commit()

    result, findings_created = evaluate_mfa_control(db, org.id, evidence_item.id)
    if findings_created and user:
        notify(db, org.id, "New finding from evidence upload",
               f"Evaluating {file.filename} created {findings_created} new finding(s).", severity="warning")
    if user:
        log_action(db, org.id, user.email, "evidence.upload", file.filename)

    if "text/html" in accept:
        return RedirectResponse(url="/evidence", status_code=303)

    return schemas.UploadResponse(
        evidence_item_id=evidence_item.id, parsed_rows=len(parsed_rows),
        evaluation_status=result.status, findings_created=findings_created,
    )


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    results = db.query(models.ControlResult).filter(
        models.ControlResult.organization_id == user.organization_id
    ).order_by(models.ControlResult.evaluated_at.desc()).limit(200).all()
    return templates.TemplateResponse("history.html", base_ctx(
        request, user, db, results=results, active="history"))


# -- Risk Register --------------------------------------------------------------

@app.get("/risks", response_class=HTMLResponse)
def risks_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    risks = db.query(models.Risk).filter(
        models.Risk.organization_id == user.organization_id
    ).order_by(models.Risk.created_at.desc()).all()
    risks = sorted(risks, key=lambda r: r.score, reverse=True)
    return templates.TemplateResponse("risks.html", base_ctx(
        request, user, db, risks=risks, active="risks"))


@app.post("/risks/create")
def create_risk(request: Request, db: Session = Depends(get_db),
                 title: str = Form(...), category: str = Form(""), description: str = Form(""),
                 likelihood: int = Form(3), impact: int = Form(3), owner: str = Form(""),
                 treatment: str = Form("mitigate")):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    risk = models.Risk(
        organization_id=user.organization_id, title=title, category=category, description=description,
        likelihood=likelihood, impact=impact, owner=owner, treatment=treatment,
    )
    db.add(risk)
    db.commit()
    log_action(db, user.organization_id, user.email, "risk.create", title)
    notify(db, user.organization_id, "New risk logged", f"'{title}' was added to the Risk Register.", "info")
    return RedirectResponse(url="/risks", status_code=303)


@app.post("/risks/{risk_id}/status")
def update_risk_status(risk_id: str, request: Request, db: Session = Depends(get_db),
                        status: str = Form(...)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
    if risk:
        risk.status = status
        risk.updated_at = datetime.utcnow()
        db.commit()
        log_action(db, user.organization_id, user.email, "risk.status", f"{risk.title} -> {status}")
    return RedirectResponse(url="/risks", status_code=303)


# -- Policy Manager --------------------------------------------------------------

@app.get("/policies", response_class=HTMLResponse)
def policies_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    policies = db.query(models.Policy).filter(
        models.Policy.organization_id == user.organization_id
    ).order_by(models.Policy.title).all()
    return templates.TemplateResponse("policies.html", base_ctx(
        request, user, db, policies=policies, active="policies"))


@app.post("/policies/create")
def create_policy(request: Request, db: Session = Depends(get_db),
                   title: str = Form(...), category: str = Form(""), owner: str = Form(""),
                   linked_framework: str = Form(""), body: str = Form("")):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    policy = models.Policy(
        organization_id=user.organization_id, title=title, category=category,
        owner=owner, linked_framework=linked_framework, body=body,
    )
    db.add(policy)
    db.commit()
    log_action(db, user.organization_id, user.email, "policy.create", title)
    return RedirectResponse(url="/policies", status_code=303)


@app.post("/policies/{policy_id}/status")
def update_policy_status(policy_id: str, request: Request, db: Session = Depends(get_db),
                          status: str = Form(...)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    policy = db.query(models.Policy).filter(models.Policy.id == policy_id).first()
    if policy:
        policy.status = status
        policy.updated_at = datetime.utcnow()
        db.commit()
        log_action(db, user.organization_id, user.email, "policy.status", f"{policy.title} -> {status}")
    return RedirectResponse(url="/policies", status_code=303)


# -- Document Library --------------------------------------------------------------

@app.get("/documents", response_class=HTMLResponse)
def documents_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    documents = db.query(models.Document).filter(
        models.Document.organization_id == user.organization_id
    ).order_by(models.Document.uploaded_at.desc()).all()
    return templates.TemplateResponse("documents.html", base_ctx(
        request, user, db, documents=documents, active="documents"))


@app.post("/documents/upload")
async def upload_document(request: Request, db: Session = Depends(get_db),
                           title: str = Form(...), category: str = Form(""), notes: str = Form(""),
                           file: UploadFile | None = File(None)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    file_name, file_path = None, None
    if file and file.filename:
        file_bytes = await file.read()
        file_path, _ = save_upload(file_bytes, file.filename)
        file_name = file.filename
    doc = models.Document(
        organization_id=user.organization_id, title=title, category=category, notes=notes,
        file_name=file_name, file_path=file_path,
    )
    db.add(doc)
    db.commit()
    log_action(db, user.organization_id, user.email, "document.upload", title)
    return RedirectResponse(url="/documents", status_code=303)


# -- Workflow & Tasks --------------------------------------------------------------

@app.get("/workflow", response_class=HTMLResponse)
def workflow_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    tasks = db.query(models.WorkflowTask).filter(
        models.WorkflowTask.organization_id == user.organization_id
    ).order_by(models.WorkflowTask.created_at.desc()).all()
    stages = ["backlog", "in_progress", "review", "done"]
    board = {s: [t for t in tasks if t.stage == s] for s in stages}
    return templates.TemplateResponse("workflow.html", base_ctx(
        request, user, db, board=board, stages=stages, active="workflow"))


@app.post("/workflow/create")
def create_task(request: Request, db: Session = Depends(get_db),
                 title: str = Form(...), assignee: str = Form(""), due_date: str = Form("")):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    db.add(models.WorkflowTask(
        organization_id=user.organization_id, title=title, assignee=assignee, due_date=due_date,
    ))
    db.commit()
    log_action(db, user.organization_id, user.email, "task.create", title)
    return RedirectResponse(url="/workflow", status_code=303)


@app.post("/workflow/{task_id}/stage")
def update_task_stage(task_id: str, request: Request, db: Session = Depends(get_db), stage: str = Form(...)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    task = db.query(models.WorkflowTask).filter(models.WorkflowTask.id == task_id).first()
    if task:
        task.stage = stage
        task.updated_at = datetime.utcnow()
        db.commit()
    return RedirectResponse(url="/workflow", status_code=303)


# -- Vendor Management --------------------------------------------------------------

@app.get("/vendors", response_class=HTMLResponse)
def vendors_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    vendors = db.query(models.Vendor).filter(
        models.Vendor.organization_id == user.organization_id
    ).order_by(models.Vendor.name).all()
    return templates.TemplateResponse("vendors.html", base_ctx(
        request, user, db, vendors=vendors, active="vendors"))


@app.post("/vendors/create")
def create_vendor(request: Request, db: Session = Depends(get_db),
                   name: str = Form(...), service_provided: str = Form(""),
                   risk_tier: str = Form("medium"), contact_email: str = Form("")):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    db.add(models.Vendor(
        organization_id=user.organization_id, name=name, service_provided=service_provided,
        risk_tier=risk_tier, contact_email=contact_email,
    ))
    db.commit()
    log_action(db, user.organization_id, user.email, "vendor.create", name)
    return RedirectResponse(url="/vendors", status_code=303)


# -- Notifications --------------------------------------------------------------

@app.get("/notifications", response_class=HTMLResponse)
def notifications_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    items = db.query(models.Notification).filter(
        models.Notification.organization_id == user.organization_id
    ).order_by(models.Notification.created_at.desc()).all()
    return templates.TemplateResponse("notifications.html", base_ctx(
        request, user, db, items=items, active="notifications"))


@app.post("/notifications/read-all")
def mark_all_read(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    db.query(models.Notification).filter(
        models.Notification.organization_id == user.organization_id
    ).update({"is_read": True})
    db.commit()
    return RedirectResponse(url="/notifications", status_code=303)


# -- AI Assistant --------------------------------------------------------------

@app.get("/assistant", response_class=HTMLResponse)
def assistant_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse("assistant.html", base_ctx(
        request, user, db, answer=None, question=None, active="assistant"))


@app.post("/assistant/ask", response_class=HTMLResponse)
def assistant_ask(request: Request, db: Session = Depends(get_db), question: str = Form(...)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    answer = ai_assistant_reply(db, user.organization_id, question)
    return templates.TemplateResponse("assistant.html", base_ctx(
        request, user, db, answer=answer, question=question, active="assistant"))


# -- Reports --------------------------------------------------------------

@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    fw_scores = compliance_by_framework(db, user.organization_id)
    open_findings = db.query(models.Finding).filter(
        models.Finding.organization_id == user.organization_id, models.Finding.status == "open"
    ).count()
    open_risks = db.query(models.Risk).filter(
        models.Risk.organization_id == user.organization_id, models.Risk.status == "open"
    ).count()
    return templates.TemplateResponse("reports.html", base_ctx(
        request, user, db, fw_scores=fw_scores, open_findings=open_findings,
        open_risks=open_risks, active="reports"))


@app.get("/reports/export.csv")
def export_report_csv(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    fw_scores = compliance_by_framework(db, user.organization_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Framework", "Version", "Total Controls", "Evaluated", "Passed", "Failed", "Score (%)"])
    for row in fw_scores:
        writer.writerow([
            row["framework"].name, row["framework"].version, row["total_controls"],
            row["evaluated"], row["passed"], row["failed"],
            row["score"] if row["score"] is not None else "N/A",
        ])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=controltrace_compliance_report.csv"
    })


# -- Audit Log --------------------------------------------------------------

@app.get("/audit-log", response_class=HTMLResponse)
def audit_log_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    entries = db.query(models.AuditLogEntry).filter(
        models.AuditLogEntry.organization_id == user.organization_id
    ).order_by(models.AuditLogEntry.created_at.desc()).limit(300).all()
    return templates.TemplateResponse("audit_log.html", base_ctx(
        request, user, db, entries=entries, active="audit-log"))


# -- User Management (admin only) --------------------------------------------------------------

@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Administrator access required")
    users = db.query(models.User).filter(models.User.organization_id == user.organization_id).all()
    return templates.TemplateResponse("users.html", base_ctx(
        request, user, db, users=users, roles=ROLE_LABELS, active="users"))


@app.post("/users/create")
def create_user(request: Request, db: Session = Depends(get_db),
                 email: str = Form(...), full_name: str = Form(""), password: str = Form(...),
                 role: str = Form("viewer")):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Administrator access required")
    existing = db.query(models.User).filter(models.User.email == email.strip().lower()).first()
    if not existing:
        db.add(models.User(
            organization_id=user.organization_id, email=email.strip().lower(), full_name=full_name,
            password_hash=hash_password(password), role=role,
        ))
        db.commit()
        log_action(db, user.organization_id, user.email, "user.create", email)
    return RedirectResponse(url="/users", status_code=303)


# -- Organization Settings (admin only) --------------------------------------------------------------

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Administrator access required")
    org = db.query(models.Organization).filter(models.Organization.id == user.organization_id).first()
    return templates.TemplateResponse("settings.html", base_ctx(
        request, user, db, org=org, active="settings"))


@app.post("/settings/update")
def update_settings(request: Request, db: Session = Depends(get_db),
                     name: str = Form(...), industry: str = Form("")):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Administrator access required")
    org = db.query(models.Organization).filter(models.Organization.id == user.organization_id).first()
    org.name = name
    org.industry = industry
    db.commit()
    log_action(db, user.organization_id, user.email, "settings.update", name)
    return RedirectResponse(url="/settings", status_code=303)


# -- Integrations (informational) --------------------------------------------------------------

@app.get("/integrations", response_class=HTMLResponse)
def integrations_page(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if isinstance(user, RedirectResponse):
        return user
    catalog = [
        {"name": "AWS Security Hub", "category": "Cloud Security", "status": "planned"},
        {"name": "Microsoft Entra ID", "category": "Identity", "status": "planned"},
        {"name": "Google Workspace", "category": "Identity", "status": "planned"},
        {"name": "Jira", "category": "Ticketing", "status": "planned"},
        {"name": "Slack", "category": "Notifications", "status": "planned"},
        {"name": "CSV / Manual Upload", "category": "Evidence", "status": "active"},
    ]
    return templates.TemplateResponse("integrations.html", base_ctx(
        request, user, db, catalog=catalog, active="integrations"))
