# Incident Response Pipeline - Task Roadmap

This roadmap details the operational tasks required to build, test, and document the Automated Cloud Incident Response Pipeline.

---

## Task List

### Phase 1: Workspace & Security Setup
- [x] Create `tasks.md` roadmap specification.
- [x] Create `.gitignore` to prevent credential and state leaks.

### Phase 2: Core Incident Response Logic & Orchestration
- [x] Build `incident_responder.py` core containment module:
  - Security Alert Parser (Supports AWS GuardDuty / GCP SCC payload schemas).
  - IAM Containment: Revoke active sessions, attach `DenyAll` quarantine policy.
  - Compute Containment: Detach production security groups, attach `quarantine-isolation-sg`, request snapshot.
  - Structured JSON Logging module with ISO-8601 timestamps and containment status metrics.
- [x] Design `orchestration_workflow.json`:
  - AWS Step Functions / GCP Workflows JSON definition mapping trigger -> decision tree -> containment execution -> alert notification.

### Phase 3: Demo & Proof of Concept Execution
- [x] Build `simulate_alert.py` integration test suite:
  - Simulate High-Severity Malware Alert on Virtual Machine (`i-0a8b9c1d2e3f45678`).
  - Simulate Unauthorized Access Alert on Compromised IAM User (`sec-analyst-temp`).
- [x] Execute simulation runner and capture outputs in `demo_output.txt`.

### Phase 4: Enterprise Documentation & Git Versioning
- [x] Create enterprise-grade `README.md` with badges, problem statement, Mermaid architecture diagram, feature matrix, and deployment guide.
- [x] Initialize Git repository, stage files, and create clean initial commit.
