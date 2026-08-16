import csv
import hashlib
from pathlib import Path
from sqlalchemy.orm import Session
from . import models

TRUTHY = {"yes", "true", "1", "y"}
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def save_upload(file_bytes: bytes, filename: str) -> tuple[str, str]:
    digest = hashlib.sha256(file_bytes).hexdigest()
    safe_name = f"{digest[:12]}_{filename}"
    path = UPLOAD_DIR / safe_name
    path.write_bytes(file_bytes)
    return str(path), digest


def parse_mfa_csv(file_path: str) -> list[dict]:
    rows = []
    with open(file_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"User", "MFA Enabled", "Is Admin"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError("CSV must contain columns: User, MFA Enabled, Is Admin")
        for row in reader:
            user = (row.get("User") or "").strip()
            if not user:
                continue
            mfa_enabled = (row.get("MFA Enabled") or "").strip().lower() in TRUTHY
            is_admin = (row.get("Is Admin") or "").strip().lower() in TRUTHY
            rows.append({
                "subject_identifier": user,
                "mfa_enabled": mfa_enabled,
                "is_admin": is_admin,
            })
    return rows


def seed_defaults(db: Session):
    org = db.query(models.Organization).first()
    if not org:
        org = models.Organization(name="Demo Organization", industry="Technology")
        db.add(org)
        db.flush()
    from .auth import hash_password

    user = db.query(models.User).filter(models.User.email == "admin@controltrace.local").first()
    if not user:
        user = models.User(
            organization_id=org.id,
            email="admin@controltrace.local",
            full_name="System Administrator",
            password_hash=hash_password("Mente1122"),
            role="org_admin",
        )
        db.add(user)

    auditor = db.query(models.User).filter(models.User.email == "auditor@controltrace.local").first()
    if not auditor:
        auditor = models.User(
            organization_id=org.id,
            email="auditor@controltrace.local",
            full_name="Compliance Auditor",
            password_hash=hash_password("Auditor123"),
            role="auditor",
        )
        db.add(auditor)

    viewer = db.query(models.User).filter(models.User.email == "viewer@controltrace.local").first()
    if not viewer:
        viewer = models.User(
            organization_id=org.id,
            email="viewer@controltrace.local",
            full_name="Read-Only Viewer",
            password_hash=hash_password("Viewer123"),
            role="viewer",
        )
        db.add(viewer)

    db.commit()
    return org, user


def seed_sample_workspace_data(db: Session):
    """Populate the newer modules (risks, policies, documents, vendors,
    notifications) with a handful of realistic starter records so the UI
    isn't empty on first run. Safe to call repeatedly - only inserts when
    the tables are empty."""
    org = db.query(models.Organization).first()
    if not org:
        return

    if db.query(models.Risk).count() == 0:
        sample_risks = [
            ("Unpatched internet-facing servers", "Vulnerability Management", 3, 4, "IT Operations", "mitigate"),
            ("Single point of failure - primary data center", "Business Continuity", 2, 5, "Infrastructure Lead", "mitigate"),
            ("Third-party vendor with excessive data access", "Third-Party Risk", 3, 3, "Vendor Management", "mitigate"),
            ("Departing employee access not revoked promptly", "Access Control", 3, 3, "IT Security", "mitigate"),
            ("Legacy application without MFA support", "Identity & Access", 4, 4, "Application Owner", "mitigate"),
            ("Insufficient backup testing cadence", "Business Continuity", 2, 4, "IT Operations", "mitigate"),
        ]
        for title, cat, like, imp, owner, treat in sample_risks:
            db.add(models.Risk(
                organization_id=org.id, title=title, category=cat,
                likelihood=like, impact=imp, owner=owner, treatment=treat,
                status="open",
            ))

    if db.query(models.Policy).count() == 0:
        sample_policies = [
            ("Information Security Policy", "Governance", "approved", "CISO", "NIST Cybersecurity Framework"),
            ("Access Control Policy", "Access Management", "approved", "IT Security", "ISO/IEC 27001"),
            ("Incident Response Plan", "Operations", "in_review", "Security Operations", "NIST Cybersecurity Framework"),
            ("Data Classification & Handling Policy", "Data Governance", "approved", "Data Protection Officer", "GDPR"),
            ("Vendor Risk Management Policy", "Third-Party Risk", "draft", "Procurement", "SOC 2"),
            ("Acceptable Use Policy", "Governance", "approved", "HR / IT", "CIS Critical Security Controls"),
            ("Business Continuity & Disaster Recovery Plan", "Operations", "in_review", "Infrastructure Lead", "ISO 22301"),
        ]
        for title, cat, status, owner, link in sample_policies:
            db.add(models.Policy(
                organization_id=org.id, title=title, category=cat, status=status,
                owner=owner, linked_framework=link,
                body=f"Summary and control statements for the {title} go here. "
                     f"Attach the full policy document in the Document Library and link it to this record.",
            ))

    if db.query(models.Vendor).count() == 0:
        sample_vendors = [
            ("CloudHost Infrastructure Inc.", "Cloud hosting / IaaS", "critical", "active"),
            ("SecureMail Gateway Co.", "Email security gateway", "medium", "active"),
            ("PayProcess Financial Services", "Payment processing", "high", "active"),
            ("HR Talent Suite", "HR / payroll SaaS", "medium", "active"),
            ("BackupVault Storage", "Offsite backup storage", "high", "active"),
        ]
        for name, service, tier, status in sample_vendors:
            db.add(models.Vendor(
                organization_id=org.id, name=name, service_provided=service,
                risk_tier=tier, status=status,
            ))

    if db.query(models.Notification).count() == 0:
        db.add(models.Notification(
            organization_id=org.id, title="Welcome to ControlTrace AI",
            message="Your compliance workspace is set up. Upload evidence, review frameworks, "
                    "and start tracking risks and remediation tasks.",
            severity="info",
        ))

    db.commit()


def seed_frameworks_and_controls(db: Session):

    all_frameworks = [
        # Original 6
        {"name": "NIST Cybersecurity Framework", "version": "CSF 2.0",      "description": "Broad enterprise cyber risk management for any industry. 6 functions: Govern, Identify, Protect, Detect, Respond, Recover."},
        {"name": "ISO/IEC 27001",                "version": "2022 Edition",  "description": "International standard for Information Security Management Systems (ISMS). 93 controls across 4 domains."},
        {"name": "CIS Critical Security Controls","version": "v8",           "description": "Technical blueprint to stop the most common active cyber threats. 18 controls with 153 safeguards."},
        {"name": "NIST SP 800-53",               "version": "Rev. 5",        "description": "Mandatory for U.S. Federal systems. 1000+ controls across 20 control families."},
        {"name": "PCI DSS",                      "version": "v4.0",          "description": "Security standard for companies handling credit card transactions. 12 requirements with 300+ sub-controls."},
        {"name": "SOC 2",                        "version": "2017",          "description": "Trust Services Criteria for U.S. technology and cloud/SaaS providers. 5 principles."},
        # New 20
        {"name": "FedRAMP",         "version": "Rev. 5",    "description": "Federal Risk and Authorization Management Program for cloud services used by U.S. federal agencies."},
        {"name": "FISMA",           "version": "2014",      "description": "Federal Information Security Modernization Act — mandatory for all U.S. federal agencies."},
        {"name": "CMMC",            "version": "2.0",       "description": "Cybersecurity Maturity Model Certification — required for U.S. Department of Defense contractors."},
        {"name": "CJIS",            "version": "5.9",       "description": "Criminal Justice Information Services Security Policy — required for agencies accessing FBI criminal data."},
        {"name": "ITAR",            "version": "Current",   "description": "International Traffic in Arms Regulations — controls export of defense articles and services."},
        {"name": "HIPAA",           "version": "2013",      "description": "Health Insurance Portability and Accountability Act — protects patient health information."},
        {"name": "HITECH",          "version": "2009",      "description": "Health Information Technology for Economic and Clinical Health Act — extends HIPAA enforcement."},
        {"name": "21 CFR Part 11",  "version": "Current",   "description": "FDA regulation for electronic records and signatures in life sciences and pharmaceutical industries."},
        {"name": "SOX",             "version": "2002",      "description": "Sarbanes-Oxley Act — financial reporting and internal controls for publicly traded companies."},
        {"name": "GLBA",            "version": "Current",   "description": "Gramm-Leach-Bliley Act — financial institutions must protect customer financial information."},
        {"name": "FFIEC",           "version": "Current",   "description": "Federal Financial Institutions Examination Council — IT examination handbook for financial institutions."},
        {"name": "GDPR",            "version": "2018",      "description": "General Data Protection Regulation — EU regulation for data protection and privacy."},
        {"name": "ISO 27017",       "version": "2015",      "description": "Code of practice for information security controls for cloud services."},
        {"name": "ISO 27018",       "version": "2019",      "description": "Code of practice for protection of personally identifiable information in public clouds."},
        {"name": "ISO 22301",       "version": "2019",      "description": "International standard for business continuity management systems."},
        {"name": "NERC CIP",        "version": "v7",        "description": "North American Electric Reliability Corporation Critical Infrastructure Protection — energy sector."},
        {"name": "HITRUST CSF",     "version": "v11",       "description": "Health Information Trust Alliance Common Security Framework — healthcare security certification."},
        {"name": "COBIT",           "version": "2019",      "description": "Control Objectives for Information Technologies — IT governance and management framework."},
        {"name": "SWIFT CSP",       "version": "2024",      "description": "SWIFT Customer Security Programme — mandatory security controls for SWIFT network participants."},
        {"name": "SOC 1",           "version": "2017",      "description": "Service Organization Control 1 — controls over financial reporting for service organizations."},
    ]

    for fw in all_frameworks:
        existing = db.query(models.Framework).filter(models.Framework.name == fw["name"]).first()
        if not existing:
            db.add(models.Framework(**fw))
    db.commit()

    def fw(name):
        return db.query(models.Framework).filter(models.Framework.name == name).first()

    all_controls = [
        # ── NIST CSF 2.0 ──────────────────────────────────────────────
        ("NIST Cybersecurity Framework","CSF-GV.OC-01","Organizational Mission Understanding","The organizational mission is understood and informs cybersecurity risk management.","medium","Govern - Organizational Context"),
        ("NIST Cybersecurity Framework","CSF-GV.OC-02","Internal Stakeholders Understanding","Internal stakeholders with cybersecurity risk management roles are identified.","medium","Govern - Organizational Context"),
        ("NIST Cybersecurity Framework","CSF-GV.OC-03","Legal Requirements Understanding","Legal, regulatory, and contractual cybersecurity obligations are understood.","high","Govern - Organizational Context"),
        ("NIST Cybersecurity Framework","CSF-GV.RM-01","Risk Management Strategy","Risk management objectives are established and agreed to by organizational stakeholders.","high","Govern - Risk Management Strategy"),
        ("NIST Cybersecurity Framework","CSF-GV.RM-02","Risk Appetite Established","Risk appetite and risk tolerance statements are established and communicated.","high","Govern - Risk Management Strategy"),
        ("NIST Cybersecurity Framework","CSF-GV.RM-03","Cybersecurity Risk Management Integrated","Organizational cybersecurity risk management is integrated into enterprise risk management.","high","Govern - Risk Management Strategy"),
        ("NIST Cybersecurity Framework","CSF-GV.RR-01","Roles and Responsibilities","Organizational leadership is responsible and accountable for cybersecurity risk.","high","Govern - Roles & Responsibilities"),
        ("NIST Cybersecurity Framework","CSF-GV.RR-02","Roles Established","Roles and responsibilities for cybersecurity are established and communicated.","medium","Govern - Roles & Responsibilities"),
        ("NIST Cybersecurity Framework","CSF-GV.PO-01","Policy Established","Policy for managing cybersecurity risks is established based on organizational context.","medium","Govern - Policy"),
        ("NIST Cybersecurity Framework","CSF-GV.PO-02","Policy Reviewed","Cybersecurity policy is reviewed, updated, communicated, and enforced.","medium","Govern - Policy"),
        ("NIST Cybersecurity Framework","CSF-ID.AM-01","Asset Inventory - Hardware","Hardware assets are inventoried.","high","Identify - Asset Management"),
        ("NIST Cybersecurity Framework","CSF-ID.AM-02","Asset Inventory - Software","Software assets are inventoried.","high","Identify - Asset Management"),
        ("NIST Cybersecurity Framework","CSF-ID.AM-03","Network Representation","Organizational communication and data flows are mapped.","medium","Identify - Asset Management"),
        ("NIST Cybersecurity Framework","CSF-ID.AM-05","Asset Prioritization","Assets are prioritized based on classification, criticality, and business value.","high","Identify - Asset Management"),
        ("NIST Cybersecurity Framework","CSF-ID.RA-01","Vulnerability Identification","Vulnerabilities in assets are identified, validated, and recorded.","high","Identify - Risk Assessment"),
        ("NIST Cybersecurity Framework","CSF-ID.RA-02","Threat Intelligence","Cyber threat intelligence is received from information sharing forums and sources.","high","Identify - Risk Assessment"),
        ("NIST Cybersecurity Framework","CSF-ID.RA-05","Risk Determination","Threats, vulnerabilities, likelihoods, and impacts are used to understand risk.","high","Identify - Risk Assessment"),
        ("NIST Cybersecurity Framework","CSF-PR.AA-01","Identity Management","Identities and credentials for authorized users, services, and hardware are managed.","high","Protect - Identity Management"),
        ("NIST Cybersecurity Framework","CSF-PR.AA-02","MFA Implemented","Identities are proofed and bound to credentials based on the context of interactions.","high","Protect - Identity Management"),
        ("NIST Cybersecurity Framework","CSF-PR.AA-03","Users Authenticated","Users, services, and hardware are authenticated.","high","Protect - Identity Management"),
        ("NIST Cybersecurity Framework","CSF-PR.AA-05","Access Permissions Managed","Access permissions, entitlements, and authorizations are defined and managed.","high","Protect - Identity Management"),
        ("NIST Cybersecurity Framework","CSF-PR.AT-01","Awareness Training","Personnel are provided with awareness and training to perform cybersecurity tasks.","medium","Protect - Awareness & Training"),
        ("NIST Cybersecurity Framework","CSF-PR.DS-01","Data at Rest Protected","The confidentiality, integrity, and availability of data-at-rest are protected.","high","Protect - Data Security"),
        ("NIST Cybersecurity Framework","CSF-PR.DS-02","Data in Transit Protected","The confidentiality, integrity, and availability of data-in-transit are protected.","high","Protect - Data Security"),
        ("NIST Cybersecurity Framework","CSF-PR.IR-01","Configuration Management","Baseline configurations are established and maintained.","medium","Protect - Infrastructure Resilience"),
        ("NIST Cybersecurity Framework","CSF-PR.PS-01","Patch Management","Software is maintained to reduce exploitation risk.","high","Protect - Platform Security"),
        ("NIST Cybersecurity Framework","CSF-DE.AE-02","Event Analysis","Potentially adverse events are analyzed to characterize the events.","high","Detect - Adverse Event Analysis"),
        ("NIST Cybersecurity Framework","CSF-DE.AE-03","Event Correlation","Information is correlated from multiple sources to achieve integrated detection.","high","Detect - Adverse Event Analysis"),
        ("NIST Cybersecurity Framework","CSF-DE.AE-06","Incident Declared","A process exists to declare incidents based on adverse event analysis.","high","Detect - Adverse Event Analysis"),
        ("NIST Cybersecurity Framework","CSF-DE.CM-01","Networks Monitored","Networks and network services are monitored to find potentially adverse events.","high","Detect - Continuous Monitoring"),
        ("NIST Cybersecurity Framework","CSF-DE.CM-03","Personnel Activity Monitored","Personnel activity is monitored to find potentially adverse events.","medium","Detect - Continuous Monitoring"),
        ("NIST Cybersecurity Framework","CSF-RS.MA-01","Incident Managed","Incidents are managed using the incident response plan.","high","Respond - Incident Management"),
        ("NIST Cybersecurity Framework","CSF-RS.CO-02","Stakeholders Notified","Incidents are reported to internal and external stakeholders as required.","high","Respond - Incident Response Reporting"),
        ("NIST Cybersecurity Framework","CSF-RC.RP-01","Recovery Plan Executed","The recovery portion of the incident response plan is executed.","high","Recover - Incident Recovery Plan Execution"),
        ("NIST Cybersecurity Framework","CSF-RC.CO-03","Recovery Communicated","Recovery activities are communicated to relevant internal and external stakeholders.","medium","Recover - Incident Recovery Communication"),
        # ── ISO/IEC 27001 ──────────────────────────────────────────────
        ("ISO/IEC 27001","ISO-5.1","Policies for Information Security","Information security policies are defined, approved by management, published and communicated.","medium","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.2","Information Security Roles","Responsibilities for information security roles are defined and allocated.","medium","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.3","Segregation of Duties","Conflicting duties and areas of responsibility are segregated.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.7","Threat Intelligence","Information relating to information security threats is collected and analyzed.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.9","Inventory of Information Assets","An inventory of information assets and associated owners is developed and maintained.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.12","Classification of Information","Information is classified according to the security needs of the organization.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.14","Information Transfer","Information transfer rules, procedures, and controls are in place for all transfer types.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.15","Access Control","Rules to control physical and logical access to information and assets are established.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.16","Identity Management","The full lifecycle of identities is managed.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.17","Authentication Information","Allocation and management of authentication information is controlled by a management process.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.18","Access Rights","Access rights to information and assets are provisioned, reviewed, modified, and removed.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.23","Cloud Services Security","Processes for acquisition, use, management, and exit of cloud services are established.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.24","Incident Planning","The organization plans and prepares for managing information security incidents.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.26","Response to Incidents","Information security incidents are responded to in accordance with documented procedures.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.29","Business Continuity Planning","Plans for information security continuity are embedded into BCM systems.","high","Organizational Controls"),
        ("ISO/IEC 27001","ISO-5.31","Legal Requirements","Legal, statutory, regulatory, and contractual requirements are identified and documented.","medium","Organizational Controls"),
        ("ISO/IEC 27001","ISO-6.1","Screening","Background verification checks on all candidates are carried out prior to joining.","high","People Controls"),
        ("ISO/IEC 27001","ISO-6.3","Security Awareness and Training","Personnel receive appropriate security awareness, education, and training.","medium","People Controls"),
        ("ISO/IEC 27001","ISO-6.7","Remote Working","Security measures are implemented when personnel work remotely.","high","People Controls"),
        ("ISO/IEC 27001","ISO-7.1","Physical Security Perimeters","Security perimeters are defined and used to protect sensitive areas.","high","Physical Controls"),
        ("ISO/IEC 27001","ISO-7.4","Physical Security Monitoring","Premises are continuously monitored for unauthorized physical access.","high","Physical Controls"),
        ("ISO/IEC 27001","ISO-8.1","User Endpoint Devices","Information stored on, processed by, or accessible via user endpoint devices is protected.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.2","Privileged Access Rights","The allocation and use of privileged access rights is restricted and managed.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.5","Secure Authentication","Secure authentication technologies and procedures are implemented.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.7","Protection Against Malware","Protection against malware is implemented and supported by user awareness.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.8","Management of Technical Vulnerabilities","Information about technical vulnerabilities is obtained and appropriate action is taken.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.9","Configuration Management","Configurations of hardware, software, and networks are established, documented, and monitored.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.12","Data Leakage Prevention","Data leakage prevention measures are applied to systems and networks.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.15","Logging","Logs that record activities, exceptions, and events are produced, stored, and reviewed.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.16","Monitoring Activities","Networks, systems, and applications are monitored for anomalous behaviour.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.20","Networks Security","Networks and network devices are secured, managed, and controlled.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.24","Use of Cryptography","Rules for effective use of cryptography are defined and implemented.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.25","Secure Development Life Cycle","Rules for secure development of software and systems are established and applied.","high","Technological Controls"),
        ("ISO/IEC 27001","ISO-8.32","Change Management","Changes to information processing facilities and systems are managed.","medium","Technological Controls"),
        # ── CIS Controls ──────────────────────────────────────────────
        ("CIS Critical Security Controls","CIS-1.1","Enterprise Asset Inventory","Establish and maintain an accurate inventory of all enterprise assets.","high","CIS-01: Inventory & Control of Enterprise Assets"),
        ("CIS Critical Security Controls","CIS-2.1","Software Asset Inventory","Establish and maintain a list of all authorized software.","high","CIS-02: Inventory & Control of Software Assets"),
        ("CIS Critical Security Controls","CIS-3.1","Data Management Process","Establish and maintain a data management process.","high","CIS-03: Data Protection"),
        ("CIS Critical Security Controls","CIS-3.6","Encrypt Data on End-User Devices","Encrypt data on end-user devices containing sensitive data.","high","CIS-03: Data Protection"),
        ("CIS Critical Security Controls","CIS-3.11","Encrypt Sensitive Data at Rest","Encrypt sensitive data at rest on servers, applications, and databases.","high","CIS-03: Data Protection"),
        ("CIS Critical Security Controls","CIS-4.1","Establish Secure Configurations","Establish and maintain a secure configuration process for enterprise assets.","high","CIS-04: Secure Configuration"),
        ("CIS Critical Security Controls","CIS-4.7","Manage Default Accounts","Manage default accounts on enterprise assets and software.","high","CIS-04: Secure Configuration"),
        ("CIS Critical Security Controls","CIS-5.1","Account Inventory","Establish and maintain an inventory of all accounts managed in the enterprise.","high","CIS-05: Account Management"),
        ("CIS Critical Security Controls","CIS-5.2","Use Unique Passwords","Use unique passwords for all enterprise assets where passwords are used.","high","CIS-05: Account Management"),
        ("CIS Critical Security Controls","CIS-5.3","Disable Dormant Accounts","Delete or disable any dormant accounts after a period of inactivity.","high","CIS-05: Account Management"),
        ("CIS Critical Security Controls","CIS-5.4","Restrict Administrator Privileges","Restrict administrator privileges to dedicated administrator accounts.","high","CIS-05: Account Management"),
        ("CIS Critical Security Controls","CIS-6.1","Establish Access Granting Process","Establish and follow a process for granting access to enterprise assets.","high","CIS-06: Access Control Management"),
        ("CIS Critical Security Controls","CIS-6.2","Establish Access Revoking Process","Establish and follow a process for revoking access to enterprise assets.","high","CIS-06: Access Control Management"),
        ("CIS Critical Security Controls","CIS-6.3","Require MFA for Administrative Access","Require MFA for all user accounts that have administrative access.","high","CIS-06: Access Control Management"),
        ("CIS Critical Security Controls","CIS-6.4","Require MFA for Remote Access","Require MFA for all remote network access.","high","CIS-06: Access Control Management"),
        ("CIS Critical Security Controls","CIS-6.5","Require MFA for Cloud Systems","Require MFA for all accounts used to access cloud environments.","high","CIS-06: Access Control Management"),
        ("CIS Critical Security Controls","CIS-7.1","Establish Vulnerability Management Process","Establish and maintain a documented vulnerability management process.","high","CIS-07: Continuous Vulnerability Management"),
        ("CIS Critical Security Controls","CIS-7.3","Automated OS Patch Management","Perform operating system updates on enterprise assets.","high","CIS-07: Continuous Vulnerability Management"),
        ("CIS Critical Security Controls","CIS-7.4","Automated Application Patch Management","Perform application updates on enterprise assets.","high","CIS-07: Continuous Vulnerability Management"),
        ("CIS Critical Security Controls","CIS-8.1","Establish Audit Log Management Process","Establish and maintain an audit log management process.","high","CIS-08: Audit Log Management"),
        ("CIS Critical Security Controls","CIS-8.2","Collect Audit Logs","Collect audit logs to detect anomalous activity and understand attacker techniques.","high","CIS-08: Audit Log Management"),
        ("CIS Critical Security Controls","CIS-8.11","Conduct Audit Log Reviews","Conduct reviews of audit logs to detect anomalies or abnormal events.","high","CIS-08: Audit Log Management"),
        ("CIS Critical Security Controls","CIS-10.1","Deploy Anti-Malware Software","Deploy and maintain anti-malware software on all enterprise assets.","high","CIS-10: Malware Defenses"),
        ("CIS Critical Security Controls","CIS-11.2","Perform Automated Backups","Perform automated backups of in-scope enterprise assets.","high","CIS-11: Data Recovery"),
        ("CIS Critical Security Controls","CIS-13.1","Centralize Security Event Alerting","Centralize security event alerting across enterprise assets.","high","CIS-13: Network Monitoring and Defense"),
        ("CIS Critical Security Controls","CIS-13.3","Deploy Network Intrusion Detection","Deploy a network intrusion detection solution on enterprise assets.","high","CIS-13: Network Monitoring and Defense"),
        ("CIS Critical Security Controls","CIS-14.1","Establish Security Awareness Program","Establish and maintain a security awareness program.","medium","CIS-14: Security Awareness & Skills Training"),
        ("CIS Critical Security Controls","CIS-17.1","Designate Personnel for Incident Management","Designate one key person as the point of contact for incident response activities.","high","CIS-17: Incident Response Management"),
        ("CIS Critical Security Controls","CIS-17.4","Establish Incident Response Process","Establish and maintain an incident response process that addresses roles and responsibilities.","high","CIS-17: Incident Response Management"),
        ("CIS Critical Security Controls","CIS-18.1","Establish Penetration Testing Program","Establish and maintain a penetration testing program appropriate for the enterprise.","high","CIS-18: Penetration Testing"),
        # ── NIST SP 800-53 ──────────────────────────────────────────────
        ("NIST SP 800-53","800-AC-1","Access Control Policy and Procedures","Develop, document, and disseminate an access control policy.","medium","AC: Access Control"),
        ("NIST SP 800-53","800-AC-2","Account Management","Manage system accounts including establishing, activating, modifying, reviewing, and removing accounts.","high","AC: Access Control"),
        ("NIST SP 800-53","800-AC-3","Access Enforcement","Enforce approved authorizations for logical access to information.","high","AC: Access Control"),
        ("NIST SP 800-53","800-AC-5","Separation of Duties","Separate duties of individuals to reduce risk of malevolent activity.","high","AC: Access Control"),
        ("NIST SP 800-53","800-AC-6","Least Privilege","Employ the concept of least privilege, allowing only authorized accesses required to accomplish tasks.","high","AC: Access Control"),
        ("NIST SP 800-53","800-AC-17","Remote Access","Establish and document usage restrictions and connection requirements for remote access.","high","AC: Access Control"),
        ("NIST SP 800-53","800-AT-2","Awareness Training","Provide awareness training to system users as part of initial training.","medium","AT: Awareness & Training"),
        ("NIST SP 800-53","800-AU-2","Event Logging","Identify the types of events that the system is capable of logging.","high","AU: Audit & Accountability"),
        ("NIST SP 800-53","800-AU-6","Audit Record Review","Review and analyze system audit records for indications of inappropriate or unusual activity.","high","AU: Audit & Accountability"),
        ("NIST SP 800-53","800-AU-9","Protection of Audit Information","Protect audit information and tools from unauthorized access, modification, and deletion.","high","AU: Audit & Accountability"),
        ("NIST SP 800-53","800-CA-7","Continuous Monitoring","Develop a system-level continuous monitoring strategy.","high","CA: Assessment & Authorization"),
        ("NIST SP 800-53","800-CM-2","Baseline Configuration","Develop and maintain a baseline configuration of the system.","high","CM: Configuration Management"),
        ("NIST SP 800-53","800-CM-6","Configuration Settings","Establish and document configuration settings for technology products.","high","CM: Configuration Management"),
        ("NIST SP 800-53","800-CM-7","Least Functionality","Configure the system to provide only essential capabilities.","high","CM: Configuration Management"),
        ("NIST SP 800-53","800-CP-9","System Backup","Conduct backups of user-level, system-level, and system documentation information.","high","CP: Contingency Planning"),
        ("NIST SP 800-53","800-CP-10","System Recovery","Provide for the recovery and reconstitution of the system to a known state after a disruption.","high","CP: Contingency Planning"),
        ("NIST SP 800-53","800-IA-2","Identification and Authentication","Uniquely identify and authenticate organizational users and processes.","high","IA: Identification & Authentication"),
        ("NIST SP 800-53","800-IA-5","Authenticator Management","Manage system authenticators by verifying identity of individuals before distributing authenticators.","high","IA: Identification & Authentication"),
        ("NIST SP 800-53","800-IR-4","Incident Handling","Implement an incident handling capability for security incidents.","high","IR: Incident Response"),
        ("NIST SP 800-53","800-IR-6","Incident Reporting","Report incidents to appropriate authorities within a defined time period.","high","IR: Incident Response"),
        ("NIST SP 800-53","800-PE-2","Physical Access Authorizations","Develop, approve, and maintain a list of individuals with authorized access to facilities.","high","PE: Physical & Environmental"),
        ("NIST SP 800-53","800-PE-3","Physical Access Control","Enforce physical access authorizations at entry and exit points.","high","PE: Physical & Environmental"),
        ("NIST SP 800-53","800-PS-3","Personnel Screening","Screen individuals prior to authorizing access to the system.","high","PS: Personnel Security"),
        ("NIST SP 800-53","800-RA-3","Risk Assessment","Conduct risk assessments and document risk assessment results.","high","RA: Risk Assessment"),
        ("NIST SP 800-53","800-RA-5","Vulnerability Monitoring and Scanning","Monitor and scan for vulnerabilities in the system on a defined frequency.","high","RA: Risk Assessment"),
        ("NIST SP 800-53","800-SC-7","Boundary Protection","Monitor and control communications at the external boundary and key internal boundaries.","high","SC: System & Communications Protection"),
        ("NIST SP 800-53","800-SC-8","Transmission Confidentiality and Integrity","Implement cryptographic mechanisms to prevent unauthorized disclosure during transmission.","high","SC: System & Communications Protection"),
        ("NIST SP 800-53","800-SC-28","Protection of Information at Rest","Implement cryptographic mechanisms to prevent unauthorized disclosure at rest.","high","SC: System & Communications Protection"),
        ("NIST SP 800-53","800-SI-2","Flaw Remediation","Identify, report, and correct information system flaws.","high","SI: System & Information Integrity"),
        ("NIST SP 800-53","800-SI-3","Malicious Code Protection","Implement malicious code protection mechanisms at system entry and exit points.","high","SI: System & Information Integrity"),
        ("NIST SP 800-53","800-SI-4","System Monitoring","Monitor the system to detect attacks and indicators of potential attacks.","high","SI: System & Information Integrity"),
        ("NIST SP 800-53","800-SR-2","Supply Chain Risk Management Plan","Develop a plan for managing supply chain risks.","high","SR: Supply Chain Risk Management"),
        # ── PCI DSS ──────────────────────────────────────────────
        ("PCI DSS","PCI-1.1","Install and Maintain Network Security Controls","Establish and implement firewall and router configuration standards.","high","Req 1: Network Security Controls"),
        ("PCI DSS","PCI-1.3","Network Access to Cardholder Data Environment","Network access to and from the cardholder data environment is restricted.","high","Req 1: Network Security Controls"),
        ("PCI DSS","PCI-2.1","Processes and Mechanisms for Secure Configurations","Processes and mechanisms for applying secure configurations are defined.","high","Req 2: Secure Configurations"),
        ("PCI DSS","PCI-2.2","System Components Configured Securely","System components are configured and managed securely.","high","Req 2: Secure Configurations"),
        ("PCI DSS","PCI-3.2","Storage of Account Data is Kept to a Minimum","Account data storage is kept to a minimum.","high","Req 3: Protect Stored Account Data"),
        ("PCI DSS","PCI-3.4","PAN Rendered Unreadable Anywhere Stored","Primary account numbers are protected with strong cryptography wherever stored.","high","Req 3: Protect Stored Account Data"),
        ("PCI DSS","PCI-4.2","PAN Protected with Strong Cryptography in Transit","PAN is protected with strong cryptography during transmission.","high","Req 4: Protect Cardholder Data in Transit"),
        ("PCI DSS","PCI-5.2","Malware Solution Deployed","Malware solution is deployed on all system components.","high","Req 5: Malware Protection"),
        ("PCI DSS","PCI-6.3","Security Vulnerabilities Identified and Addressed","Security vulnerabilities are identified and addressed.","high","Req 6: Secure Systems & Software"),
        ("PCI DSS","PCI-6.4","Public-Facing Web Applications Protected","Public-facing web applications are protected against attacks.","high","Req 6: Secure Systems & Software"),
        ("PCI DSS","PCI-7.2","Access to System Components is Restricted","Access to system components and data is appropriately defined and assigned.","high","Req 7: Restrict Access"),
        ("PCI DSS","PCI-8.2","User IDs and Authentication Credentials are Managed","All user IDs and authentication credentials are managed throughout their lifecycle.","high","Req 8: Identify Users & Authenticate Access"),
        ("PCI DSS","PCI-8.4","Multi-Factor Authentication is Implemented","Multi-factor authentication is implemented to secure access into the CDE.","high","Req 8: Identify Users & Authenticate Access"),
        ("PCI DSS","PCI-9.2","Physical Access Controls","Physical access controls manage entry into facilities and systems storing cardholder data.","high","Req 9: Restrict Physical Access"),
        ("PCI DSS","PCI-10.2","Audit Logs are Implemented","Audit logs are implemented to support detection of anomalies and suspicious activity.","high","Req 10: Log and Monitor All Access"),
        ("PCI DSS","PCI-10.3","Audit Logs are Protected","Audit logs are protected from destruction and unauthorized modifications.","high","Req 10: Log and Monitor All Access"),
        ("PCI DSS","PCI-10.4","Audit Logs are Reviewed","Audit logs are reviewed to identify anomalies or suspicious activity.","high","Req 10: Log and Monitor All Access"),
        ("PCI DSS","PCI-10.5","Audit Log History is Retained","Retain audit log history for at least 12 months.","high","Req 10: Log and Monitor All Access"),
        ("PCI DSS","PCI-11.3","External and Internal Vulnerabilities are Managed","External and internal vulnerabilities are regularly identified, prioritized, and addressed.","high","Req 11: Test Security Regularly"),
        ("PCI DSS","PCI-11.4","External and Internal Penetration Testing","External and internal penetration testing is regularly performed.","high","Req 11: Test Security Regularly"),
        ("PCI DSS","PCI-12.1","Information Security Policy","A comprehensive information security policy is defined, published, maintained, and disseminated.","medium","Req 12: Support Information Security"),
        ("PCI DSS","PCI-12.10","Suspected and Confirmed Security Incidents","Suspected and confirmed security incidents are responded to immediately.","high","Req 12: Support Information Security"),
        # ── SOC 2 ──────────────────────────────────────────────
        ("SOC 2","SOC2-CC1.1","COSO Principle 1 - Integrity and Ethics","The entity demonstrates a commitment to integrity and ethical values.","medium","CC1: Control Environment"),
        ("SOC 2","SOC2-CC3.2","COSO Principle 7 - Identifies and Analyzes Risk","The entity identifies risks to the achievement of its objectives and analyzes risks.","high","CC3: Risk Assessment"),
        ("SOC 2","SOC2-CC5.1","COSO Principle 10 - Selects and Develops Controls","The entity selects and develops control activities that contribute to risk mitigation.","high","CC5: Control Activities"),
        ("SOC 2","SOC2-CC6.1","Logical Access Security Measures","The entity implements logical access security software and infrastructure.","high","CC6: Logical & Physical Access Controls"),
        ("SOC 2","SOC2-CC6.2","New Internal Users Registered and Authorized","Prior to issuing credentials, the entity registers and authorizes new internal users.","high","CC6: Logical & Physical Access Controls"),
        ("SOC 2","SOC2-CC6.3","Access Removed When No Longer Required","The entity removes access to protected information assets when no longer required.","high","CC6: Logical & Physical Access Controls"),
        ("SOC 2","SOC2-CC6.6","Logical Access - External Threats","The entity implements logical access security measures to protect against external threats.","high","CC6: Logical & Physical Access Controls"),
        ("SOC 2","SOC2-CC6.7","Transmission and Movement of Data","The entity restricts the transmission and movement of information to authorized parties.","high","CC6: Logical & Physical Access Controls"),
        ("SOC 2","SOC2-CC6.8","Malicious Software Prevention","The entity implements controls to prevent or detect and act upon malicious software.","high","CC6: Logical & Physical Access Controls"),
        ("SOC 2","SOC2-CC7.1","Configuration and Vulnerability Management","The entity uses detection and monitoring procedures to identify changes to configurations.","high","CC7: System Operations"),
        ("SOC 2","SOC2-CC7.2","Monitor System Components for Anomalies","The entity monitors system components and the operation of those components for anomalies.","high","CC7: System Operations"),
        ("SOC 2","SOC2-CC7.4","Respond to Security Incidents","The entity responds to identified security incidents by executing a defined incident response program.","high","CC7: System Operations"),
        ("SOC 2","SOC2-CC8.1","Changes Managed","The entity authorizes, designs, develops, configures, documents, and approves changes to infrastructure.","high","CC8: Change Management"),
        ("SOC 2","SOC2-CC9.2","Vendor and Business Partner Risk Management","The entity assesses and manages risks associated with vendors and business partners.","high","CC9: Risk Mitigation"),
        ("SOC 2","SOC2-A1.1","Availability - Capacity Planning","The entity measures current usage and forecast capacity requirements.","medium","A1: Availability"),
        ("SOC 2","SOC2-A1.3","Availability - Recovery Plan Testing","The entity tests recovery plan procedures to determine effectiveness.","high","A1: Availability"),
        ("SOC 2","SOC2-C1.1","Confidentiality - Information Identified","The entity identifies and maintains confidential information to meet the entity's objectives.","high","C1: Confidentiality"),
        ("SOC 2","SOC2-P1.1","Privacy - Notice and Communication","The entity provides notice about its privacy practices to data subjects.","medium","P: Privacy"),
        # ── FedRAMP ──────────────────────────────────────────────
        ("FedRAMP","FED-AC-2","Account Management","Manage cloud service accounts including creation, activation, modification, review, and removal.","high","Access Control"),
        ("FedRAMP","FED-AC-17","Remote Access","Establish and document usage restrictions and connection requirements for remote access.","high","Access Control"),
        ("FedRAMP","FED-AC-22","Publicly Accessible Content","Designate individuals authorized to post publicly accessible content on systems.","medium","Access Control"),
        ("FedRAMP","FED-IA-2","Multi-Factor Authentication","Implement MFA for network access to privileged and non-privileged accounts.","high","Identity & Authentication"),
        ("FedRAMP","FED-IA-3","Device Identification","Uniquely identify and authenticate devices before establishing connections.","medium","Identity & Authentication"),
        ("FedRAMP","FED-AU-2","Audit Events","Determine which events require auditing and coordinate with other organizations.","medium","Audit & Accountability"),
        ("FedRAMP","FED-AU-6","Audit Record Review","Review and analyze audit records for indications of inappropriate or unusual activity.","high","Audit & Accountability"),
        ("FedRAMP","FED-AU-12","Audit Record Generation","Provide audit record generation capability for defined auditable events.","high","Audit & Accountability"),
        ("FedRAMP","FED-CM-6","Configuration Settings","Establish and document configuration settings for IT products employed within the system.","high","Configuration Management"),
        ("FedRAMP","FED-IR-4","Incident Handling","Implement incident handling capability including preparation, detection, and eradication.","high","Incident Response"),
        ("FedRAMP","FED-IR-6","Incident Reporting","Report incidents to FedRAMP PMO and US-CERT within defined timeframes.","high","Incident Response"),
        ("FedRAMP","FED-SC-7","Boundary Protection","Monitor and control communications at external and internal boundaries.","high","System & Communications"),
        ("FedRAMP","FED-SC-28","Protection of Information at Rest","Implement cryptographic mechanisms to prevent unauthorized disclosure at rest.","high","System & Communications"),
        ("FedRAMP","FED-SI-2","Flaw Remediation","Identify, report, and correct system flaws within FedRAMP-defined timeframes.","high","System Integrity"),
        ("FedRAMP","FED-RA-5","Vulnerability Monitoring","Monitor and scan for vulnerabilities in the system on a monthly basis.","high","Risk Assessment"),
        ("FedRAMP","FED-SA-9","External System Services","Require external service providers to comply with federal security requirements.","high","System Acquisition"),
        # ── FISMA ──────────────────────────────────────────────
        ("FISMA","FISMA-1","Information Security Program","Develop, document, and implement an agency-wide information security program.","high","Program Management"),
        ("FISMA","FISMA-2","System Inventory","Maintain an inventory of all federal information systems.","high","Program Management"),
        ("FISMA","FISMA-3","Risk Categorization","Categorize information systems based on FIPS 199 impact levels.","high","Risk Management"),
        ("FISMA","FISMA-4","Security Controls Selection","Select and implement minimum security controls per FIPS 200 and NIST SP 800-53.","high","Risk Management"),
        ("FISMA","FISMA-5","Security Assessment","Assess security controls to determine effectiveness.","high","Assessment & Authorization"),
        ("FISMA","FISMA-6","Authorization to Operate","Authorize system operation based on risk determination by authorizing official.","high","Assessment & Authorization"),
        ("FISMA","FISMA-7","Continuous Monitoring","Monitor security controls on an ongoing basis and report to OMB annually.","high","Continuous Monitoring"),
        ("FISMA","FISMA-8","Incident Response Reporting","Report security incidents to US-CERT within required timeframes.","high","Incident Response"),
        ("FISMA","FISMA-9","Security Training","Provide security awareness training to all personnel with system access.","medium","Awareness & Training"),
        ("FISMA","FISMA-10","Plan of Action & Milestones","Develop and maintain POA&M to track remediation of security weaknesses.","high","Remediation"),
        ("FISMA","FISMA-11","Configuration Management","Establish baseline configurations and manage changes to systems.","high","Configuration Management"),
        ("FISMA","FISMA-12","Contingency Planning","Develop, test, and update contingency plans for information systems.","high","Contingency Planning"),
        # ── CMMC ──────────────────────────────────────────────
        ("CMMC","CMMC-AC.1.001","Limit System Access","Limit information system access to authorized users and devices.","high","Access Control"),
        ("CMMC","CMMC-AC.1.002","Limit Transaction Types","Limit system access to the types of transactions authorized users are permitted to execute.","high","Access Control"),
        ("CMMC","CMMC-AC.3.017","Separation of Duties","Separate the duties of individuals to reduce the risk of malevolent activity.","high","Access Control"),
        ("CMMC","CMMC-AC.3.018","Least Privilege","Employ the principle of least privilege, including for security functions.","high","Access Control"),
        ("CMMC","CMMC-IA.1.076","Identify Users","Identify information system users, processes, or devices.","high","Identification & Authentication"),
        ("CMMC","CMMC-IA.1.077","Authenticate Users","Authenticate the identities of users, processes, or devices before allowing access.","high","Identification & Authentication"),
        ("CMMC","CMMC-IA.3.083","Use Multi-Factor Authentication","Use multi-factor authentication for local and network access to privileged accounts.","high","Identification & Authentication"),
        ("CMMC","CMMC-AU.2.041","Audit User Activity","Ensure that the actions of individual users can be traced to those users.","high","Audit & Accountability"),
        ("CMMC","CMMC-AU.2.042","Create Audit Logs","Create and retain system audit logs to enable monitoring and investigation.","high","Audit & Accountability"),
        ("CMMC","CMMC-CM.2.061","Establish Baseline Configurations","Establish and maintain baseline configurations of organizational systems.","high","Configuration Management"),
        ("CMMC","CMMC-IR.2.092","Establish Incident Response","Establish an operational incident-handling capability for systems.","high","Incident Response"),
        ("CMMC","CMMC-IR.2.093","Track and Report Incidents","Track, document, and report incidents to appropriate officials.","high","Incident Response"),
        ("CMMC","CMMC-PS.2.127","Screen Personnel","Screen individuals prior to authorizing access to systems containing CUI.","high","Personnel Security"),
        ("CMMC","CMMC-RA.2.141","Scan for Vulnerabilities","Periodically scan for vulnerabilities and remediate identified vulnerabilities.","high","Risk Assessment"),
        ("CMMC","CMMC-SC.1.175","Monitor Communications","Monitor, control, and protect communications at external boundaries.","high","System & Communications"),
        ("CMMC","CMMC-SI.1.210","Identify and Manage Flaws","Identify, report, and correct information and system flaws in a timely manner.","high","System Integrity"),
        ("CMMC","CMMC-SI.1.211","Protect Against Malware","Provide protection from malicious code at appropriate locations.","high","System Integrity"),
        # ── CJIS ──────────────────────────────────────────────
        ("CJIS","CJIS-5.1.1","Security Awareness Training","All personnel with access to CJI must complete security awareness training within 6 months.","medium","Awareness & Training"),
        ("CJIS","CJIS-5.2.1","Security Policy","Each agency must have a formal documented security policy.","medium","Policy"),
        ("CJIS","CJIS-5.3.1","Incident Response","Agencies must have an incident response plan for CJI-related incidents.","high","Incident Response"),
        ("CJIS","CJIS-5.4.1","Auditing and Accountability","All access to CJI must be logged and auditable.","high","Audit & Accountability"),
        ("CJIS","CJIS-5.5.1","Access Control","Access to CJI must be restricted to authorized personnel only.","high","Access Control"),
        ("CJIS","CJIS-5.5.6","Session Lock","Systems must lock after a maximum of 30 minutes of inactivity.","medium","Access Control"),
        ("CJIS","CJIS-5.6.1","Identification and Authentication","Agencies must uniquely identify and authenticate all users accessing CJI.","high","Identification & Authentication"),
        ("CJIS","CJIS-5.6.2.2","Advanced Authentication","Advanced authentication required for CJI access from outside secure locations.","high","Identification & Authentication"),
        ("CJIS","CJIS-5.7.1","Configuration Management","Agencies must establish baseline configurations for all systems accessing CJI.","high","Configuration Management"),
        ("CJIS","CJIS-5.8.1","Media Protection","All media containing CJI must be protected and sanitized before disposal.","high","Media Protection"),
        ("CJIS","CJIS-5.9.1","Physical Protection","Physical access to systems containing CJI must be controlled and monitored.","high","Physical Protection"),
        ("CJIS","CJIS-5.11.1","Formal Audits","Agencies must conduct triennial security audits of CJI systems.","high","Audit & Accountability"),
        ("CJIS","CJIS-5.12.1","Personnel Security","All personnel must undergo fingerprint-based background checks before CJI access.","high","Personnel Security"),
        # ── ITAR ──────────────────────────────────────────────
        ("ITAR","ITAR-120.1","Registration Requirement","Any person who manufactures or exports defense articles must register with DDTC.","high","Registration & Licensing"),
        ("ITAR","ITAR-122.1","Export License Requirement","A license is required to export any defense article listed on the USML.","high","Export Controls"),
        ("ITAR","ITAR-125.1","Technical Data Controls","Control export of technical data related to defense articles.","high","Technical Data"),
        ("ITAR","ITAR-126.1","Prohibited Exports","No defense articles may be exported to embargoed countries.","high","Export Controls"),
        ("ITAR","ITAR-AC.1","Access Controls for Technical Data","Restrict access to ITAR-controlled technical data to authorized U.S. persons only.","high","Access Control"),
        ("ITAR","ITAR-TR.1","Technology Transfer Controls","Prevent unauthorized transfer of controlled technology to foreign persons.","high","Technology Transfer"),
        ("ITAR","ITAR-RK.1","Recordkeeping Requirements","Maintain records of all ITAR-controlled exports for a minimum of 5 years.","medium","Recordkeeping"),
        ("ITAR","ITAR-EP.1","Employee Training","Train all employees with access to ITAR-controlled data on export compliance.","medium","Training"),
        ("ITAR","ITAR-CP.1","Compliance Program","Establish a formal ITAR compliance program with designated compliance officer.","high","Compliance Program"),
        # ── HIPAA ──────────────────────────────────────────────
        ("HIPAA","HIPAA-164.308a1","Security Management Process","Implement policies to prevent, detect, contain, and correct security violations.","high","Administrative Safeguards"),
        ("HIPAA","HIPAA-164.308a2","Assigned Security Responsibility","Identify the security official responsible for HIPAA security policies.","high","Administrative Safeguards"),
        ("HIPAA","HIPAA-164.308a3","Workforce Security","Implement procedures to ensure workforce access to ePHI is appropriate.","high","Administrative Safeguards"),
        ("HIPAA","HIPAA-164.308a4","Information Access Management","Implement policies for authorizing access to ePHI.","high","Administrative Safeguards"),
        ("HIPAA","HIPAA-164.308a5","Security Awareness Training","Implement a security awareness and training program for all workforce members.","medium","Administrative Safeguards"),
        ("HIPAA","HIPAA-164.308a6","Security Incident Procedures","Implement policies and procedures to address security incidents.","high","Administrative Safeguards"),
        ("HIPAA","HIPAA-164.308a7","Contingency Plan","Establish policies for responding to emergencies that damage systems with ePHI.","high","Administrative Safeguards"),
        ("HIPAA","HIPAA-164.310a1","Facility Access Controls","Implement policies to limit physical access to systems containing ePHI.","high","Physical Safeguards"),
        ("HIPAA","HIPAA-164.310c","Workstation Security","Implement physical safeguards for workstations accessing ePHI.","high","Physical Safeguards"),
        ("HIPAA","HIPAA-164.310d1","Device and Media Controls","Implement policies for disposal and re-use of hardware and electronic media.","high","Physical Safeguards"),
        ("HIPAA","HIPAA-164.312a1","Access Control","Implement technical policies to allow only authorized persons to access ePHI.","high","Technical Safeguards"),
        ("HIPAA","HIPAA-164.312a2","Audit Controls","Implement hardware and software to record access to information systems with ePHI.","high","Technical Safeguards"),
        ("HIPAA","HIPAA-164.312b","Integrity Controls","Implement security measures to ensure ePHI is not improperly altered or destroyed.","high","Technical Safeguards"),
        ("HIPAA","HIPAA-164.312c1","Person Authentication","Implement procedures to verify a person seeking access to ePHI is who they claim.","high","Technical Safeguards"),
        ("HIPAA","HIPAA-164.312e1","Transmission Security","Implement technical security to guard against unauthorized access to ePHI in transit.","high","Technical Safeguards"),
        ("HIPAA","HIPAA-164.314a1","Business Associate Contracts","Obtain satisfactory assurances from business associates handling ePHI.","high","Organizational Requirements"),
        ("HIPAA","HIPAA-164.316a","Policies and Procedures","Implement reasonable and appropriate policies and procedures to comply with HIPAA.","medium","Policies & Procedures"),
        ("HIPAA","HIPAA-164.316b1","Documentation","Maintain HIPAA-related policies, procedures, and records for 6 years.","medium","Policies & Procedures"),
        # ── HITECH ──────────────────────────────────────────────
        ("HITECH","HITECH-13400","Breach Notification - Individual","Notify affected individuals of breaches of unsecured PHI within 60 days.","high","Breach Notification"),
        ("HITECH","HITECH-13402","Breach Notification - Media","Notify prominent media outlets of breaches affecting more than 500 residents of a state.","high","Breach Notification"),
        ("HITECH","HITECH-13407","Breach Notification - Secretary","Notify HHS Secretary of all breaches of unsecured PHI annually or immediately if >500.","high","Breach Notification"),
        ("HITECH","HITECH-13408","Business Associate Liability","Business associates are directly liable for HIPAA violations under HITECH.","high","Business Associate"),
        ("HITECH","HITECH-13410","Civil Monetary Penalties","Implement controls to avoid willful neglect violations subject to mandatory penalties.","high","Compliance"),
        ("HITECH","HITECH-13411","Audit Requirements","HHS must conduct periodic audits of covered entities and business associates.","medium","Audit"),
        ("HITECH","HITECH-SEC.1","Encryption of PHI","Encrypt PHI at rest and in transit to qualify for breach notification safe harbor.","high","Technical Controls"),
        ("HITECH","HITECH-SEC.2","Access Logging","Log all access to ePHI systems to support breach investigation.","high","Technical Controls"),
        ("HITECH","HITECH-SEC.3","Risk Analysis","Conduct thorough risk analysis of all ePHI held by the organization.","high","Risk Management"),
        # ── 21 CFR Part 11 ──────────────────────────────────────────────
        ("21 CFR Part 11","CFR11-11.10a","Validation of Systems","Validate systems to ensure accuracy, reliability, and consistent performance.","high","System Validation"),
        ("21 CFR Part 11","CFR11-11.10b","Record Generation","Ability to generate accurate and complete copies of records in human readable form.","high","Records Management"),
        ("21 CFR Part 11","CFR11-11.10d","System Access Limitation","Limit system access to authorized individuals.","high","Access Control"),
        ("21 CFR Part 11","CFR11-11.10e","Audit Trails","Use secure, computer-generated, time-stamped audit trails to record date and time of entries.","high","Audit Trail"),
        ("21 CFR Part 11","CFR11-11.10g","Authority Checks","Use authority checks to ensure only authorized individuals can use the system.","high","Access Control"),
        ("21 CFR Part 11","CFR11-11.10i","Training Requirements","Determine that persons who develop, maintain, or use electronic systems have education and training.","medium","Training"),
        ("21 CFR Part 11","CFR11-11.50","Signature Manifestations","Signed electronic records shall contain information associated with the signing.","high","Electronic Signatures"),
        ("21 CFR Part 11","CFR11-11.70","Signature/Record Linking","Electronic signatures shall be linked to their respective electronic records.","high","Electronic Signatures"),
        ("21 CFR Part 11","CFR11-11.100","General Signature Requirements","Electronic signatures shall be unique to one individual and not reused by anyone else.","high","Electronic Signatures"),
        ("21 CFR Part 11","CFR11-11.200","Signature Components","Electronic signatures shall employ at least two distinct identification components.","high","Electronic Signatures"),
        ("21 CFR Part 11","CFR11-11.300","Controls for Identification Codes","Controls for identification codes and passwords must include periodic recalls and revisions.","high","Access Control"),
        # ── SOX ──────────────────────────────────────────────
        ("SOX","SOX-302","CEO/CFO Certification","CEO and CFO must personally certify accuracy of financial reports.","high","Financial Reporting"),
        ("SOX","SOX-404","Internal Controls Assessment","Management must assess effectiveness of internal controls over financial reporting annually.","high","Internal Controls"),
        ("SOX","SOX-409","Real-Time Disclosure","Companies must disclose material changes in financial condition on a rapid and current basis.","high","Disclosure"),
        ("SOX","SOX-802","Records Destruction","Knowingly destroying records to impede federal investigations is a criminal offense.","high","Records Management"),
        ("SOX","SOX-IT.1","IT General Controls","Implement IT general controls including access, change management, and operations.","high","IT Controls"),
        ("SOX","SOX-IT.2","Access Controls","Restrict access to financial systems and data to authorized individuals only.","high","Access Control"),
        ("SOX","SOX-IT.3","Change Management","Document and approve all changes to financial systems before implementation.","high","Change Management"),
        ("SOX","SOX-IT.4","Audit Logging","Log all access to and changes in financial systems for audit purposes.","high","Audit & Accountability"),
        ("SOX","SOX-IT.5","Data Backup and Recovery","Implement backup and recovery procedures for financial data systems.","high","Business Continuity"),
        ("SOX","SOX-IT.6","Segregation of Duties","Separate duties so no single individual can complete a financial transaction end-to-end.","high","Access Control"),
        ("SOX","SOX-IT.7","Vulnerability Management","Regularly scan and remediate vulnerabilities in financial systems.","high","Risk Management"),
        # ── GLBA ──────────────────────────────────────────────
        ("GLBA","GLBA-SF.1","Information Security Program","Develop, implement, and maintain a comprehensive information security program.","high","Security Program"),
        ("GLBA","GLBA-SF.2","Risk Assessment","Identify and assess risks to customer information in each relevant area of operations.","high","Risk Assessment"),
        ("GLBA","GLBA-SF.3","Safeguards Implementation","Implement information safeguards and regularly monitor their effectiveness.","high","Safeguards"),
        ("GLBA","GLBA-SF.4","Service Provider Oversight","Oversee service providers by contract to implement appropriate safeguards.","high","Third Party"),
        ("GLBA","GLBA-PP.1","Privacy Notice","Provide clear privacy notices to customers about information sharing practices.","medium","Privacy"),
        ("GLBA","GLBA-PP.3","Limits on Disclosure","Limit disclosure of nonpublic personal information to third parties.","high","Privacy"),
        ("GLBA","GLBA-AC.1","Access Controls","Implement access controls including MFA for systems with customer financial data.","high","Access Control"),
        ("GLBA","GLBA-EN.1","Encryption","Encrypt customer financial information in transit and at rest.","high","Encryption"),
        ("GLBA","GLBA-IR.1","Incident Response Plan","Develop and implement an incident response plan for breaches of customer data.","high","Incident Response"),
        ("GLBA","GLBA-TR.1","Security Training","Train staff to implement and comply with the information security program.","medium","Training"),
        # ── FFIEC ──────────────────────────────────────────────
        ("FFIEC","FFIEC-IS.1","Information Security Program","Develop and maintain a formal information security program.","high","Information Security"),
        ("FFIEC","FFIEC-IS.2","Risk Assessment","Conduct a comprehensive risk assessment of IT systems and data.","high","Risk Assessment"),
        ("FFIEC","FFIEC-IS.3","Audit Function","Maintain an independent audit function to evaluate IT controls.","high","Audit"),
        ("FFIEC","FFIEC-IS.4","Business Continuity","Develop and test business continuity and disaster recovery plans.","high","Business Continuity"),
        ("FFIEC","FFIEC-IS.5","Third Party Management","Oversee third-party service providers with formal due diligence and contracts.","high","Third Party"),
        ("FFIEC","FFIEC-AC.1","Authentication","Implement layered authentication for online financial services.","high","Access Control"),
        ("FFIEC","FFIEC-AC.2","Privileged Access","Control and monitor privileged access to financial systems.","high","Access Control"),
        ("FFIEC","FFIEC-CM.1","Change Management","Implement formal change management processes for IT systems.","high","Change Management"),
        ("FFIEC","FFIEC-IR.1","Incident Response","Establish and test an incident response program for cybersecurity events.","high","Incident Response"),
        ("FFIEC","FFIEC-VM.1","Vulnerability Management","Implement a vulnerability management program with regular scanning.","high","Vulnerability Management"),
        # ── GDPR ──────────────────────────────────────────────
        ("GDPR","GDPR-5","Principles of Data Processing","Process personal data lawfully, fairly, transparently, and for specified purposes.","high","Data Processing Principles"),
        ("GDPR","GDPR-6","Lawful Basis for Processing","Establish and document a lawful basis for all personal data processing activities.","high","Lawful Basis"),
        ("GDPR","GDPR-7","Conditions for Consent","Obtain freely given, specific, informed, and unambiguous consent for data processing.","high","Consent"),
        ("GDPR","GDPR-15","Right of Access","Allow data subjects to obtain confirmation of and access to their personal data.","high","Data Subject Rights"),
        ("GDPR","GDPR-17","Right to Erasure","Allow data subjects to request deletion of their personal data.","high","Data Subject Rights"),
        ("GDPR","GDPR-25","Data Protection by Design","Implement data protection by design and by default in all systems.","high","Technical Measures"),
        ("GDPR","GDPR-28","Data Processing Agreements","Enter into data processing agreements with all data processors.","high","Processor Obligations"),
        ("GDPR","GDPR-30","Records of Processing Activities","Maintain records of all data processing activities.","high","Documentation"),
        ("GDPR","GDPR-32","Security of Processing","Implement appropriate technical and organizational security measures.","high","Security"),
        ("GDPR","GDPR-33","Breach Notification to Authority","Notify supervisory authority of personal data breaches within 72 hours.","high","Breach Notification"),
        ("GDPR","GDPR-34","Breach Notification to Individuals","Notify affected individuals of high-risk personal data breaches without undue delay.","high","Breach Notification"),
        ("GDPR","GDPR-35","Data Protection Impact Assessment","Conduct DPIA for processing likely to result in high risk to individuals.","high","Risk Assessment"),
        ("GDPR","GDPR-37","Data Protection Officer","Designate a DPO where required by regulation.","medium","Governance"),
        ("GDPR","GDPR-44","International Data Transfers","Ensure appropriate safeguards for transfers of personal data to third countries.","high","Data Transfers"),
        # ── ISO 27017 ──────────────────────────────────────────────
        ("ISO 27017","27017-6.3.1","Shared Roles in Cloud","Clearly define and document the shared security roles between cloud provider and customer.","high","Cloud Roles & Responsibilities"),
        ("ISO 27017","27017-8.1.1","Cloud Asset Inventory","Maintain an inventory of assets stored in or processed by cloud services.","high","Asset Management"),
        ("ISO 27017","27017-9.1.2","Cloud Access Policy","Establish and implement access control policies specific to cloud environments.","high","Access Control"),
        ("ISO 27017","27017-9.5.1","Segregation in Virtual Environments","Ensure segregation of virtual environments between different cloud customers.","high","Virtualization Security"),
        ("ISO 27017","27017-10.1.1","Cloud Cryptography Policy","Define and implement a cryptography policy for data stored in cloud services.","high","Cryptography"),
        ("ISO 27017","27017-12.4.1","Cloud Event Logging","Implement logging of cloud service administrator activities.","high","Logging & Monitoring"),
        ("ISO 27017","27017-13.1.3","Network Security in Cloud","Implement network security controls for cloud environments.","high","Network Security"),
        ("ISO 27017","27017-16.1.3","Cloud Incident Reporting","Report security incidents related to cloud services to the cloud provider.","high","Incident Management"),
        ("ISO 27017","27017-17.2.1","Cloud Business Continuity","Ensure information security continuity is planned for cloud service disruptions.","high","Business Continuity"),
        # ── ISO 27018 ──────────────────────────────────────────────
        ("ISO 27018","27018-A.1","Consent for Marketing","Do not use PII processed for cloud services for marketing without customer consent.","high","Consent"),
        ("ISO 27018","27018-A.2","Subprocessor Disclosure","Disclose to customers the use of subprocessors for handling PII.","high","Transparency"),
        ("ISO 27018","27018-A.3","Government Access Disclosure","Inform customers of government requests for access to their PII.","high","Transparency"),
        ("ISO 27018","27018-A.4","PII Return and Deletion","Return and delete PII upon termination of cloud service contract.","high","Data Lifecycle"),
        ("ISO 27018","27018-A.7","Data Breach Notification","Notify customers of personal data breaches without undue delay.","high","Breach Notification"),
        ("ISO 27018","27018-A.8","PII Minimization","Implement processes to minimize the amount of PII collected and processed.","medium","Data Minimization"),
        ("ISO 27018","27018-A.10","PII Transmission Policy","Define and implement policies for transmission of PII.","high","Data Transmission"),
        # ── ISO 22301 ──────────────────────────────────────────────
        ("ISO 22301","22301-4.1","Organization Context","Determine external and internal issues relevant to business continuity.","medium","Context"),
        ("ISO 22301","22301-6.1","Business Continuity Objectives","Establish business continuity objectives and plans to achieve them.","high","Planning"),
        ("ISO 22301","22301-8.2","Business Impact Analysis","Conduct business impact analysis to identify critical functions and recovery priorities.","high","Business Impact Analysis"),
        ("ISO 22301","22301-8.3","Risk Assessment","Perform risk assessment to identify threats to business continuity.","high","Risk Assessment"),
        ("ISO 22301","22301-8.4","Business Continuity Strategy","Establish business continuity strategies to protect prioritized activities.","high","Strategy"),
        ("ISO 22301","22301-8.5","Business Continuity Plans","Document business continuity plans for responding to disruptions.","high","Plans & Procedures"),
        ("ISO 22301","22301-8.6","Exercising and Testing","Confirm and improve effectiveness of BCM through exercises and tests.","high","Testing"),
        ("ISO 22301","22301-9.1","Monitoring and Measurement","Monitor, measure, analyze, and evaluate business continuity performance.","medium","Performance Evaluation"),
        ("ISO 22301","22301-10.1","Nonconformity and Corrective Action","Manage nonconformities and implement corrective actions.","medium","Improvement"),
        # ── NERC CIP ──────────────────────────────────────────────
        ("NERC CIP","CIP-002-5","BES Cyber System Categorization","Identify and categorize BES Cyber Systems and their associated assets.","high","Asset Identification"),
        ("NERC CIP","CIP-003-8","Security Management Controls","Specify minimum security management controls to protect BES Cyber Systems.","high","Security Management"),
        ("NERC CIP","CIP-004-6","Personnel and Training","Minimize risk to BES through personnel risk assessment and security training.","high","Personnel Security"),
        ("NERC CIP","CIP-005-6","Electronic Security Perimeters","Manage electronic access to BES Cyber Systems within Electronic Security Perimeters.","high","Network Security"),
        ("NERC CIP","CIP-006-6","Physical Security","Manage physical access to BES Cyber Systems through physical security plans.","high","Physical Security"),
        ("NERC CIP","CIP-007-6","System Security Management","Manage system security of BES Cyber Systems by specifying technical controls.","high","System Security"),
        ("NERC CIP","CIP-008-6","Incident Reporting and Response","Mitigate the risk of cybersecurity incidents by specifying incident response requirements.","high","Incident Response"),
        ("NERC CIP","CIP-009-6","Recovery Plans","Recover reliability functions performed by BES Cyber Systems after cybersecurity incidents.","high","Recovery"),
        ("NERC CIP","CIP-010-3","Configuration Change Management","Prevent unauthorized changes to BES Cyber Systems through configuration management.","high","Configuration Management"),
        ("NERC CIP","CIP-011-2","Information Protection","Prevent unauthorized access to BES Cyber System Information.","high","Information Protection"),
        ("NERC CIP","CIP-013-1","Supply Chain Risk Management","Mitigate cybersecurity risks in the supply chain for BES Cyber Systems.","high","Supply Chain"),
        # ── HITRUST CSF ──────────────────────────────────────────────
        ("HITRUST CSF","HITRUST-01","Information Protection Program","Establish and maintain an information protection program.","high","Program Management"),
        ("HITRUST CSF","HITRUST-02","Endpoint Protection","Implement controls to protect endpoints from malware and unauthorized access.","high","Endpoint Security"),
        ("HITRUST CSF","HITRUST-04","Mobile Device Security","Implement security controls for mobile devices accessing organizational data.","high","Mobile Security"),
        ("HITRUST CSF","HITRUST-06","Configuration Management","Implement configuration management controls for all systems.","high","Configuration Management"),
        ("HITRUST CSF","HITRUST-07","Vulnerability Management","Implement a vulnerability management program with regular scanning.","high","Vulnerability Management"),
        ("HITRUST CSF","HITRUST-08","Network Protection","Implement network protection controls including firewalls and IDS/IPS.","high","Network Security"),
        ("HITRUST CSF","HITRUST-09","Transmission Protection","Protect the transmission of sensitive information across networks.","high","Data Transmission"),
        ("HITRUST CSF","HITRUST-10","Password Management","Implement password management controls including complexity and rotation.","high","Access Control"),
        ("HITRUST CSF","HITRUST-11","Access Control","Implement logical access controls based on least privilege.","high","Access Control"),
        ("HITRUST CSF","HITRUST-12","Audit Logging","Implement audit logging for all systems handling sensitive information.","high","Audit & Accountability"),
        ("HITRUST CSF","HITRUST-13","Education Training Awareness","Implement security awareness training for all workforce members.","medium","Training"),
        ("HITRUST CSF","HITRUST-14","Third Party Security","Manage security risks associated with third-party relationships.","high","Third Party Management"),
        ("HITRUST CSF","HITRUST-15","Incident Management","Implement an incident management program for security events.","high","Incident Response"),
        ("HITRUST CSF","HITRUST-16","Business Continuity","Implement business continuity and disaster recovery plans.","high","Business Continuity"),
        ("HITRUST CSF","HITRUST-17","Risk Management","Implement a formal risk management program.","high","Risk Management"),
        ("HITRUST CSF","HITRUST-18","Physical Security","Implement physical security controls to protect facilities and equipment.","high","Physical Security"),
        ("HITRUST CSF","HITRUST-19","Data Protection","Implement controls to protect sensitive data throughout its lifecycle.","high","Data Protection"),
        # ── COBIT ──────────────────────────────────────────────
        ("COBIT","COBIT-EDM01","Governance Framework","Evaluate, direct, and monitor the governance system and framework.","high","Evaluate, Direct & Monitor"),
        ("COBIT","COBIT-EDM03","Risk Optimization","Ensure that IT-related enterprise risk does not exceed risk appetite.","high","Evaluate, Direct & Monitor"),
        ("COBIT","COBIT-APO01","IT Management Framework","Clarify and maintain the governance of enterprise IT management.","high","Align, Plan & Organize"),
        ("COBIT","COBIT-APO12","Risk Management","Identify, assess, and reduce IT-related risks within tolerance levels.","high","Align, Plan & Organize"),
        ("COBIT","COBIT-APO13","Security Management","Define, operate, and monitor a system for information security management.","high","Align, Plan & Organize"),
        ("COBIT","COBIT-BAI06","Change Management","Manage all changes to IT infrastructure and applications in a controlled manner.","high","Build, Acquire & Implement"),
        ("COBIT","COBIT-BAI10","Configuration Management","Manage configuration assets of IT services and infrastructure.","high","Build, Acquire & Implement"),
        ("COBIT","COBIT-DSS01","Operations Management","Manage IT operations including IT infrastructure components and facilities.","high","Deliver, Service & Support"),
        ("COBIT","COBIT-DSS02","Incident Management","Provide timely and effective response to IT incidents.","high","Deliver, Service & Support"),
        ("COBIT","COBIT-DSS04","Continuity Management","Establish and maintain a plan to enable IT and business to respond to incidents.","high","Deliver, Service & Support"),
        ("COBIT","COBIT-DSS05","Security Services","Protect IT enterprise information to maintain acceptable risk level.","high","Deliver, Service & Support"),
        ("COBIT","COBIT-MEA01","Performance Monitoring","Monitor and evaluate IT and enterprise performance.","medium","Monitor, Evaluate & Assess"),
        ("COBIT","COBIT-MEA02","Internal Controls","Continuously monitor and evaluate the internal control environment.","high","Monitor, Evaluate & Assess"),
        ("COBIT","COBIT-MEA03","External Compliance","Evaluate compliance with external requirements for IT.","high","Monitor, Evaluate & Assess"),
        # ── SWIFT CSP ──────────────────────────────────────────────
        ("SWIFT CSP","SWIFT-1.1","SWIFT Environment Protection","Restrict internet access and protect the SWIFT environment from general IT environment.","high","Network Security"),
        ("SWIFT CSP","SWIFT-1.2","Privileged Account Control","Restrict and control the allocation and usage of privileged accounts.","high","Access Control"),
        ("SWIFT CSP","SWIFT-2.1","Internal Data Flow Security","Ensure confidentiality, integrity, and authenticity of SWIFT data flows.","high","Data Security"),
        ("SWIFT CSP","SWIFT-2.2","Security Updates","Minimize technical vulnerabilities by applying security updates regularly.","high","Patch Management"),
        ("SWIFT CSP","SWIFT-2.3","System Hardening","Reduce attack surface of SWIFT-related components by hardening systems.","high","Configuration Management"),
        ("SWIFT CSP","SWIFT-2.6","Operator Session Confidentiality","Protect the confidentiality and integrity of operator sessions.","high","Session Security"),
        ("SWIFT CSP","SWIFT-2.7","Vulnerability Scanning","Identify vulnerabilities in the SWIFT environment through regular scanning.","high","Vulnerability Management"),
        ("SWIFT CSP","SWIFT-3.1","Physical Security","Prevent unauthorized physical access to sensitive equipment and facilities.","high","Physical Security"),
        ("SWIFT CSP","SWIFT-4.1","Password Policy","Implement and enforce a strong password policy for all SWIFT accounts.","high","Access Control"),
        ("SWIFT CSP","SWIFT-4.2","Multi-Factor Authentication","Implement MFA for all SWIFT interactive user accounts.","high","Authentication"),
        ("SWIFT CSP","SWIFT-5.1","Logical Access Controls","Enforce logical access controls to the SWIFT-related infrastructure.","high","Access Control"),
        ("SWIFT CSP","SWIFT-6.1","Malware Protection","Ensure malware protection on all SWIFT-related infrastructure.","high","Malware Protection"),
        ("SWIFT CSP","SWIFT-6.4","Logging and Monitoring","Record security events and detect anomalous activity in SWIFT environment.","high","Logging & Monitoring"),
        ("SWIFT CSP","SWIFT-7.1","Cyber Incident Response Planning","Define and implement a cyber incident response and recovery plan for SWIFT.","high","Incident Response"),
        ("SWIFT CSP","SWIFT-7.2","Security Training and Awareness","Ensure all staff understand SWIFT cybersecurity risks and their responsibilities.","medium","Training"),
        ("SWIFT CSP","SWIFT-7.3A","Penetration Testing","Validate security controls through regular penetration testing.","high","Security Testing"),
        ("SWIFT CSP","SWIFT-7.4A","Scenario Risk Assessment","Conduct risk assessment based on SWIFT-related threat scenarios.","high","Risk Assessment"),
        # ── SOC 1 ──────────────────────────────────────────────
        ("SOC 1","SOC1-CC1.1","Control Environment - Tone at Top","Management sets appropriate tone regarding internal controls over financial reporting.","medium","Control Environment"),
        ("SOC 1","SOC1-CC1.2","Organizational Structure","Organizational structure supports effective internal control over financial reporting.","medium","Control Environment"),
        ("SOC 1","SOC1-CC2.1","Risk Assessment Process","Management identifies and assesses risks to achieving financial reporting objectives.","high","Risk Assessment"),
        ("SOC 1","SOC1-CC3.1","Control Activities - Policies","Control activities are implemented through policies and procedures for financial reporting.","high","Control Activities"),
        ("SOC 1","SOC1-CC4.1","Information and Communication","Information relevant to financial reporting is communicated through appropriate channels.","medium","Information & Communication"),
        ("SOC 1","SOC1-CC5.1","Monitoring - Ongoing","Ongoing monitoring activities evaluate whether controls are present and functioning.","high","Monitoring"),
        ("SOC 1","SOC1-AC.1","Logical Access to Financial Systems","Access to financial systems is restricted to authorized individuals.","high","Access Control"),
        ("SOC 1","SOC1-AC.2","User Account Management","User accounts for financial systems are managed with formal procedures.","high","Access Control"),
        ("SOC 1","SOC1-AC.3","Privileged Access","Privileged access to financial systems is restricted and monitored.","high","Access Control"),
        ("SOC 1","SOC1-CH.1","Change Management","Changes to financial systems are authorized, tested, and documented.","high","Change Management"),
        ("SOC 1","SOC1-DP.1","Data Processing Integrity","Data is processed completely, accurately, and in a timely manner.","high","Data Processing"),
        ("SOC 1","SOC1-BC.1","Backup and Recovery","Financial data is backed up and recoverable within defined timeframes.","high","Business Continuity"),
    ]

    for item in all_controls:
        fw_name, code, title, desc, severity, category = item
        existing = db.query(models.Control).filter(models.Control.control_code == code).first()
        if not existing:
            framework = fw(fw_name)
            if framework:
                db.add(models.Control(
                    framework_id=framework.id,
                    control_code=code,
                    title=title,
                    description=desc,
                    severity=severity,
                    category=category,
                ))
    db.commit()


def evaluate_mfa_control(db: Session, organization_id: str, evidence_item_id: str) -> tuple[models.ControlResult, int]:
    control = db.query(models.Control).filter(models.Control.control_code == "CIS-6.3").first()
    records = (
        db.query(models.EvidenceNormalizedRecord)
        .filter(models.EvidenceNormalizedRecord.evidence_item_id == evidence_item_id)
        .all()
    )
    admin_records = [r for r in records if r.is_admin]
    non_compliant = [r for r in admin_records if not r.mfa_enabled]

    if not admin_records:
        status, score, summary = "fail", 0, "No admin rows were found in the uploaded evidence."
    elif non_compliant:
        status, score = "fail", 0
        summary = f"{len(non_compliant)} administrator account(s) are missing MFA."
    else:
        status, score = "pass", 100
        summary = f"All {len(admin_records)} administrator account(s) have MFA enabled."

    result = models.ControlResult(
        control_id=control.id,
        organization_id=organization_id,
        status=status, score=score, result_summary=summary,
    )
    db.add(result)
    db.flush()

    findings_created = 0
    if status == "fail":
        names = ", ".join([r.subject_identifier for r in non_compliant][:10]) if non_compliant else "No admin rows found"
        db.add(models.Finding(
            control_result_id=result.id,
            organization_id=organization_id,
            title="Administrative accounts missing MFA",
            description=f"Administrator accounts without MFA: {names}. Enable MFA for all privileged users.",
            severity="high", status="open",
        ))
        findings_created = 1

    db.commit()
    db.refresh(result)
    return result, findings_created


# ── Cross-cutting helpers used by the newer modules ──────────────────────

def log_action(db: Session, organization_id: str, actor_email: str | None, action: str, details: str = ""):
    db.add(models.AuditLogEntry(
        organization_id=organization_id,
        actor_email=actor_email,
        action=action,
        details=details,
    ))
    db.commit()


def notify(db: Session, organization_id: str, title: str, message: str, severity: str = "info"):
    db.add(models.Notification(
        organization_id=organization_id,
        title=title,
        message=message,
        severity=severity,
    ))
    db.commit()


def compliance_by_framework(db: Session, organization_id: str) -> list[dict]:
    """Compliance score per framework, based on the latest ControlResult
    per control within that framework."""
    frameworks = db.query(models.Framework).order_by(models.Framework.name).all()
    output = []
    for framework in frameworks:
        control_ids = [c.id for c in framework.controls]
        total_controls = len(control_ids)
        if not control_ids:
            output.append({
                "framework": framework, "total_controls": 0,
                "evaluated": 0, "passed": 0, "failed": 0, "score": None,
            })
            continue

        results = (
            db.query(models.ControlResult)
            .filter(models.ControlResult.control_id.in_(control_ids))
            .filter(models.ControlResult.organization_id == organization_id)
            .order_by(models.ControlResult.evaluated_at.desc())
            .all()
        )
        latest_by_control = {}
        for r in results:
            if r.control_id not in latest_by_control:
                latest_by_control[r.control_id] = r

        evaluated = len(latest_by_control)
        passed = sum(1 for r in latest_by_control.values() if r.status == "pass")
        failed = evaluated - passed
        score = round((passed / evaluated) * 100, 1) if evaluated else None

        output.append({
            "framework": framework, "total_controls": total_controls,
            "evaluated": evaluated, "passed": passed, "failed": failed, "score": score,
        })
    return output


def ai_assistant_reply(db: Session, organization_id: str, question: str) -> str:
    """Generates an insight-driven answer using the organization's live
    compliance data. Uses the Anthropic API for open-ended reasoning when
    ANTHROPIC_API_KEY is configured in the environment; otherwise falls back
    to a built-in, rules-based insights engine so the assistant always works
    out of the box with no external dependency."""
    import os

    open_findings = db.query(models.Finding).filter(
        models.Finding.organization_id == organization_id, models.Finding.status == "open"
    ).order_by(models.Finding.severity.desc()).all()
    open_risks = db.query(models.Risk).filter(
        models.Risk.organization_id == organization_id, models.Risk.status == "open"
    ).all()
    fw_scores = compliance_by_framework(db, organization_id)
    evaluated_scores = [f for f in fw_scores if f["score"] is not None]
    overall = round(sum(f["score"] for f in evaluated_scores) / len(evaluated_scores), 1) if evaluated_scores else None

    context_lines = [
        f"Overall compliance score across evaluated frameworks: {overall if overall is not None else 'not yet evaluated'}%",
        f"Open findings: {len(open_findings)}",
        f"Open risks: {len(open_risks)}",
    ]
    top_risks = sorted(open_risks, key=lambda r: r.score, reverse=True)[:5]
    if top_risks:
        context_lines.append("Top open risks: " + "; ".join(f"{r.title} ({r.rating})" for r in top_risks))
    if open_findings:
        context_lines.append("Sample open findings: " + "; ".join(f.title for f in open_findings[:5]))
    context = "\n".join(context_lines)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            resp = client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=600,
                system=(
                    "You are the ControlTrace AI compliance assistant. Answer using only the "
                    "organization's compliance data provided below. Be concise, specific, and "
                    "practical. Recommend concrete next actions when relevant.\n\n" + context
                ),
                messages=[{"role": "user", "content": question}],
            )
            return "".join(block.text for block in resp.content if hasattr(block, "text"))
        except Exception as e:
            return (
                "The AI Assistant couldn't reach the Anthropic API "
                f"({e.__class__.__name__}), so here's a data-driven summary instead:\n\n"
                + _rules_based_answer(question, context, overall, open_findings, top_risks)
            )

    return _rules_based_answer(question, context, overall, open_findings, top_risks)


def _rules_based_answer(question: str, context: str, overall, open_findings, top_risks) -> str:
    q = question.lower()
    lines = []
    if "risk" in q:
        if top_risks:
            lines.append("Highest-priority open risks:")
            for r in top_risks:
                lines.append(f"  - {r.title} (rating: {r.rating}, owner: {r.owner or 'unassigned'})")
        else:
            lines.append("No open risks are currently recorded in the Risk Register.")
    elif "finding" in q:
        if open_findings:
            lines.append("Open findings needing remediation:")
            for f in open_findings[:8]:
                lines.append(f"  - [{f.severity}] {f.title}")
        else:
            lines.append("No open findings right now — nice work.")
    elif "score" in q or "compliance" in q or "status" in q:
        lines.append(f"Overall compliance score across evaluated frameworks: "
                      f"{overall if overall is not None else 'not yet evaluated'}%.")
        lines.append("Upload evidence and run control evaluations to increase framework coverage.")
    else:
        lines.append("Here's a snapshot of your current compliance posture:")
        lines.append(context)
        lines.append("\nAsk me about your risks, open findings, or compliance score for more detail. "
                      "Set the ANTHROPIC_API_KEY environment variable to enable full conversational "
                      "answers powered by Claude.")
    return "\n".join(lines)
