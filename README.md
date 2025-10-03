# Cloudhunter — Autonomous Red Team Automation for Cloud Infrastructure

##  About Me & Motivation
I’m a cybersecurity student and engineer who has always been fascinated by the way attackers think. Over the past year, I’ve kept seeing stories about **data stolen from the cloud, exposed S3 buckets, and major cloud breaches**. It struck me how often these issues come down to simple misconfigurations that slip through unnoticed.

The phrase by Friedrich Nietzsche — *“If you gaze long into an abyss, the abyss also gazes into you.”* — is what motivated me to get into ethical hacking and penetration testing. To find and fix security gaps, you need to *think like an attacker*. That means understanding the mindset and techniques of people who exploit systems, but using that knowledge to protect others.

Cloudhunter started as my way of addressing that problem — building a tool that doesn’t just run static checks, but actually **simulates attacker behavior** to highlight what matters most before it becomes tomorrow’s headline.

---

##  Purpose
- Automate red team–style testing for AWS, Azure, and GCP.
- Identify **misconfigurations, CVEs, and compliance gaps**.
- Use **adaptive attack patterns** to show what an attacker would actually try.
- Provide **clear risk scoring and recommendations** to reduce noise and help teams focus.

---

##  Development Roadmap (Starting Oct 2025)
- Phase 1 (Oct–Nov 2025): CLI + AWS/Azure, CSV reports, minimal DB
- Phase 2 (Dec 2025 – Feb 2026): GCP + Dashboard, FastAPI + PG, CVSS
- Phase 3 (Mar–May 2026): Slack/Jira, Docs & OSS core

## Architecture 
```mermaid
%%{init: {"theme":"dark", "themeVariables": {
  "primaryColor": "#1e1b29",
  "primaryTextColor": "#f5f3ff",
  "primaryBorderColor": "#a78bfa",
  "lineColor": "#8b5cf6",
  "secondaryColor": "#0a0a0f",
  "tertiaryColor": "#0a0a0f",
  "noteBkgColor": "#1e1b29",
  "noteTextColor": "#ede9fe"
}} }%%
flowchart LR
  subgraph Clients[Client Layer]
    CLI[CLI (Click)<br/>- Run scans<br/>- Export CSV/JSON]
    UI[Web Dashboard (React + MUI)<br/>- Findings, CVSS, reports<br/>- Filters & search]
  end

  subgraph API[API & Orchestration (FastAPI)]
    APISVC[FastAPI REST<br/>- AuthN/AuthZ (OIDC)<br/>- Jobs API<br/>- Results API]
    SCHED[Job Scheduler / Orchestrator<br/>- Cron/RQ/Celery<br/>- Rate limits]
    WORKERS[Scan Workers (Python 3.11)<br/>- Stateless containers]
  end

  subgraph Engine[Core Scan Engine]
    SHARED[Shared Logic<br/>- Resource graph<br/>- Normalizers<br/>- Risk model (CVSS)]
    AWS[Connector: AWS (boto3)<br/>- S3, EC2, IAM]
    AZ[Connector: Azure SDK<br/>- Blob, VM, IAM]
    GCP[Connector: GCP Client Libs<br/>- GCS, GCE, IAM]
    AI[AI Layer<br/>- Adaptive attack paths<br/>- Prioritization]
  end

  subgraph Data[Data Layer]
    PG[(PostgreSQL<br/>- Findings & metadata<br/>- Users, orgs, jobs)]
    ES[(Elasticsearch / OpenSearch<br/>- Logs & events<br/>- Query analytics)]
    OBJ[(Object Storage (S3/Blob/GCS)<br/>- Report artifacts<br/>- Large JSON dumps)]
  end

  subgraph Integrations[Integrations]
    SLACK[Slack / MS Teams (Webhooks)<br/>- Critical alerts]
    JIRA[Jira<br/>- Ticket creation<br/>- Auto-triage]
  end

  subgraph Platform[Platform (Deployment)]
    K8S[Docker + Kubernetes<br/>- Autoscaling<br/>- Secrets (KMS)<br/>- Ingress]
    VAULT[Secrets Mgmt (KMS/Vault)<br/>- Cloud creds<br/>- API keys]
    MQ[Queue (Redis/RabbitMQ)<br/>- Work dispatch<br/>- Backpressure]
  end

  CLI -->|REST / gRPC (future)| APISVC
  UI -->|HTTPS / JSON| APISVC
  APISVC -->|Create scan jobs| SCHED
  SCHED -->|Dispatch| WORKERS
  WORKERS -->|Invoke checks| SHARED
  SHARED -->|SDK calls| AWS
  SHARED -->|SDK calls| AZ
  SHARED -->|SDK calls| GCP
  SHARED -->|Context → ranking| AI

  WORKERS -->|Write findings| PG
  WORKERS -->|Emit logs| ES
  WORKERS -->|Upload artifacts| OBJ

  APISVC -->|Read findings| PG
  APISVC -->|Query logs| ES
  APISVC -->|Download reports| OBJ

  APISVC -->|Alerts| SLACK
  APISVC -->|Tickets| JIRA

  K8S -.->|Pods| WORKERS
  K8S -.->|Service| APISVC
  K8S -.->|CronJobs| SCHED
  VAULT -.->|Short-lived creds| WORKERS
  VAULT -.->|OIDC/JWT secrets| APISVC
  MQ -.-> SCHED
  MQ -.-> WORKERS

  P1([Phase 1 (Oct–Nov 2025):<br/>- CLI + AWS/Azure connectors<br/>- CSV reports<br/>- PG minimal schema])
  P2([Phase 2 (Dec 2025 – Feb 2026):<br/>- GCP + Dashboard<br/>- FastAPI + PG<br/>- CVSS scoring])
  P3([Phase 3 (Mar–May 2026):<br/>- Slack/Jira<br/>- Docs & OSS core])
  P1 -.-> CLI
  P1 -.-> AWS
  P1 -.-> AZ
  P2 -.-> GCP
  P2 -.-> UI
  P2 -.-> APISVC
  P3 -.-> SLACK
  P3 -.-> JIRA

