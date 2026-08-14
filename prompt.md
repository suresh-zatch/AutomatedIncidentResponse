You are the Lead Cloud Security & Automation Engineer executing a master-level development workflow. I am the Director. Your objective is to build an Automated Incident Response Pipeline that instantly isolates compromised cloud resources (such as an infected virtual machine or exposed instance) when a critical security alert fires.

Execute the following phases autonomously. Do not stop until all tasks are complete, and use the terminal to run tests:

PHASE 1: WORKSPACE & SECURITY SETUP
- Create a `tasks.md` file outlining the build steps: 1) Mock security alert trigger, 2) Core Python isolation logic (IAM/Compute containment), 3) AWS Step Functions / GCP Workflows orchestration template, 4) Integration test script.
- Create a strict `.gitignore` file excluding venv/, .env, .tfstate, and local cache files to protect intellectual property.

PHASE 2: CORE INCIDENT RESPONSE LOGIC
- Write a Python script (`incident_responder.py`) that simulates receiving a critical security webhook (e.g., high-severity malware or unauthorized access alert).
- Implement containment logic using least-privilege principles (e.g., automatically revoking active IAM sessions for compromised users or attaching a strict isolation security group to a mock VM).

PHASE 3: DEMO & PROOF OF CONCEPT
- Write a test script called `simulate_alert.py` that triggers the incident response pipeline.
- Run the simulation via the terminal, capture the JSON execution logs proving successful automated containment, and save them into a file named `demo_output.txt`.

PHASE 4: ENTERPRISE DOCUMENTATION & GIT PREPARATION
- Generate a comprehensive, professional `README.md` containing:
  1. Project Title, Subtitle, and Security Focus badges.
  2. The Real-World Problem (SOC analyst alert fatigue and dwell time).
  3. A Mermaid.js Architecture Diagram showing the flow from Security Alert -> Orchestrator -> Automated Containment.
  4. Core Security Features (least-privilege IAM, zero-human-delay isolation).
  5. Setup instructions and a reference to the `demo_output.txt` results.
- Initialize a local git repository (`git init`), stage all files, and make a clean initial commit (`git commit -m "feat: initial private release of automated incident response pipeline"`).

Provide a final summary report once all phases are complete, including the exact terminal command I need to run to push this to my private GitHub repository.