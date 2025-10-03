<p align="center">
  <img src="./docs/logo.png" alt="Cloudhunter Logo" width="200"/>
</p>

# Cloudhunter — Autonomous Red Team Automation for Cloud Infrastructure

##  About Me & Motivation
I’m a cybersecurity student fascinated by the way attackers think. Over the past year, I’ve seen countless headlines about data stolen from the cloud — exposed S3 buckets, public blobs, and major breaches. What struck me is how often the root cause is simple: a misconfiguration left unnoticed.

I was watching Criminal Minds when an episode closed with a quote: “If you gaze long into an abyss, the abyss also gazes into you.” In that moment it hit me — attackers don’t stop. They’re always probing, always looking for the next misconfiguration or exposed bucket. Cloudhunter was born from that thought: build a tool that never stops scanning, that hunts for vulnerabilities the same way attackers do, but uses that insight to protect systems and people.

Cloudhunter started as my way of addressing that problem — building a tool that doesn’t just run static checks, but actually simulates attacker behavior to highlight what matters most before it becomes tomorrow’s headline.

---
## Design Inspiration
The name Cloudhunter and the logo are driven by the Nietzsche quote above. The eye in the logo represents vigilance and observation; the hexagon at the center symbolizes cloud infrastructure and technology. The idea of "staring into the abyss" informs the project's purpose: proactively reveal hidden risks before attackers find them.
Name: Proactively hunt cloud vulnerabilities
Logo: An eye with a tech-core (hexagon) — watchful and precise
Mission: Turn attacker mindset into a defensive advantage

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
    CLI[CLI Click - run scans - export CSV and JSON]
    UI[Web dashboard React and MUI - findings CVSS reports - filters and search]
  end

  subgraph API[API and Orchestration FastAPI]
    APISVC[FastAPI REST - authN authZ OIDC - jobs API - results API]
    SCHED[Job scheduler and orchestrator - cron RQ Celery - rate limits]
    WORKERS[Scan workers Python 3.11 - stateless containers]
  end

  subgraph Engine[Core Scan Engine]
    SHARED[Shared logic - resource graph - normalizers - risk model CVSS]
    AWS[AWS connector boto3 - S3 - EC2 - IAM]
    AZ[Azure connector SDK - Blob - VM - IAM]
    GCP[GCP connector client libs - GCS - GCE - IAM]
    AI[AI layer - adaptive attack paths - prioritization]
  end

  subgraph Data[Data Layer]
    PG[(PostgreSQL - findings and metadata - users orgs jobs)]
    ES[(Elasticsearch or OpenSearch - logs and events - query analytics)]
    OBJ[(Object storage - reports - large JSON dumps)]
  end

  subgraph Integrations[Integrations]
    SLACK[Slack or MS Teams - critical alerts]
    JIRA[Jira - ticket creation - auto triage]
  end

  subgraph Platform[Platform Deployment]
    K8S[Docker and Kubernetes - autoscaling - secrets KMS - ingress]
    VAULT[Secrets management KMS or Vault - cloud creds - API keys]
    MQ[Queue Redis or RabbitMQ - work dispatch - backpressure]
  end

  CLI -->|REST or gRPC future| APISVC
  UI -->|HTTPS JSON| APISVC
  APISVC -->|create scan jobs| SCHED
  SCHED -->|dispatch| WORKERS
  WORKERS -->|invoke checks| SHARED
  SHARED -->|SDK calls| AWS
  SHARED -->|SDK calls| AZ
  SHARED -->|SDK calls| GCP
  SHARED -->|context to ranking| AI

  WORKERS -->|write findings| PG
  WORKERS -->|emit logs| ES
  WORKERS -->|upload artifacts| OBJ

  APISVC -->|read findings| PG
  APISVC -->|query logs| ES
  APISVC -->|download reports| OBJ

  APISVC -->|alerts| SLACK
  APISVC -->|tickets| JIRA

  K8S -.->|pods| WORKERS
  K8S -.->|service| APISVC
  K8S -.->|cron jobs| SCHED
  VAULT -.->|short lived creds| WORKERS
  VAULT -.->|OIDC JWT secrets| APISVC
  MQ -.-> SCHED
  MQ -.-> WORKERS

  P1([Phase 1 Oct Nov 2025 - CLI plus AWS Azure connectors - CSV reports - PG minimal schema])
  P2([Phase 2 Dec 2025 to Feb 2026 - GCP plus dashboard - FastAPI plus PG - CVSS scoring])
  P3([Phase 3 Mar to May 2026 - Slack Jira - docs and open source core])
  P1 -.-> CLI
  P1 -.-> AWS
  P1 -.-> AZ
  P2 -.-> GCP
  P2 -.-> UI
  P2 -.-> APISVC
  P3 -.-> SLACK
  P3 -.-> JIRA
