# Cloudhunter — Autonomous Red Team Automation for Cloud Infrastructure

## 👋 About Me & Motivation
I’m a cybersecurity student and engineer who has always been fascinated by the way attackers think. Over the past year, I’ve kept seeing stories about **data stolen from the cloud, exposed S3 buckets, and major cloud breaches**. It struck me how often these issues come down to simple misconfigurations that slip through unnoticed.

The phrase by Friedrich Nietzsche — *“If you gaze long into an abyss, the abyss also gazes into you.”* — is what motivated me to get into ethical hacking and penetration testing. To find and fix security gaps, you need to *think like an attacker*. That means understanding the mindset and techniques of people who exploit systems, but using that knowledge to protect others.

Cloudhunter started as my way of addressing that problem — building a tool that doesn’t just run static checks, but actually **simulates attacker behavior** to highlight what matters most before it becomes tomorrow’s headline.

---

## 🎯 Purpose
- Automate red team–style testing for AWS, Azure, and GCP.
- Identify **misconfigurations, CVEs, and compliance gaps**.
- Use **adaptive attack patterns** to show what an attacker would actually try.
- Provide **clear risk scoring and recommendations** to reduce noise and help teams focus.

---

## 📅 Development Roadmap (Starting Oct 2025)
- Phase 1 (Oct–Nov 2025): CLI + AWS/Azure, CSV reports, minimal DB
- Phase 2 (Dec 2025 – Feb 2026): GCP + Dashboard, FastAPI + PG, CVSS
- Phase 3 (Mar–May 2026): Slack/Jira, Docs & OSS core

## 🏗️ Architecture (Mermaid)
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
    CLI[CLI (Click)\n- Run scans\n- Export CSV/JSON]
    UI[Web Dashboard (React + MUI)\n- Findings, CVSS, reports\n- Filters & search]
  end
  subgraph API[API & Orchestration (FastAPI)]
    APISVC[FastAPI REST\n- AuthN/AuthZ (OIDC)\n- Jobs API\n- Results API]
    SCHED[Job Scheduler / Orchestrator\n- Cron/RQ/Celery\n- Rate limits]
    WORKERS[Scan Workers (Python 3.11)\n- Stateless containers]
  end
  subgraph Engine[Core Scan Engine]
    SHARED[Shared Logic\n- Resource graph\n- Normalizers\n- Risk model (CVSS)]
    AWS[Connector: AWS (boto3)\n- S3, EC2, IAM]
    AZ[Connector: Azure SDK\n- Blob, VM, IAM]
    GCP[Connector: GCP Client Libs\n- GCS, GCE, IAM]
    AI[AI Layer\n- Adaptive attack paths\n- Prioritization]
  end
  subgraph Data[Data Layer]
    PG[(PostgreSQL\n- Findings & metadata\n- Users, orgs, jobs)]
    ES[(Elasticsearch / OpenSearch\n- Logs & events\n- Query analytics)]
    OBJ[(Object Storage (S3/Blob/GCS)\n- Report artifacts\n- Large JSON dumps)]
  end
  subgraph Integrations[Integrations]
    SLACK[Slack / MS Teams (Webhooks)\n- Critical alerts]
    JIRA[Jira\n- Ticket creation\n- Auto-triage]
  end
  subgraph Platform[Platform (Deployment)]
    K8S[Docker + Kubernetes\n- Autoscaling\n- Secrets (KMS)\n- Ingress]
    VAULT[Secrets Mgmt (KMS/Vault)\n- Cloud creds\n- API keys]
    MQ[Queue (Redis/RabbitMQ)\n- Work dispatch\n- Backpressure]
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
  P1([Phase 1 (Oct–Nov 2025):\n- CLI + AWS/Azure connectors\n- CSV reports\n- PG minimal schema])
  P2([Phase 2 (Dec 2025 – Feb 2026):\n- GCP + Dashboard\n- FastAPI + PG\n- CVSS scoring])
  P3([Phase 3 (Mar–May 2026):\n- Slack/Jira\n- Docs & OSS core])
  P1 -.-> CLI
  P1 -.-> AWS
  P1 -.-> AZ
  P2 -.-> GCP
  P2 -.-> UI
  P2 -.-> APISVC
  P3 -.-> SLACK
  P3 -.-> JIRA
```
