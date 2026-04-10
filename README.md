# Sentinel-X SOC Platform

Sentinel-X is an analyst-focused Security Operations Center platform built with **React + Vite**, **tRPC**, **Drizzle ORM**, **MySQL**, and an integrated detection pipeline. This upgraded version moves the project beyond CRUD-only cyber modules and adds the essential capabilities expected in a higher-level cyber security analyst portfolio platform.

## What changed in this upgrade

### 1) Real ingestion + detection pipeline
Sentinel-X now supports:
- raw log ingestion
- JSON event ingestion
- syslog ingestion
- event normalization
- offline enrichment
- Sigma-like rule matching
- confidence scoring
- alert generation
- IDS detection creation
- automatic incident creation for high-confidence detections

The pipeline is implemented in `server/security/pipeline.ts` and exposed through `siem.ingestRawEvent`.

### 2) Real enrichment pipeline
Each ingested event can be enriched with:
- IOC matches from the threat intel store
- asset context from the asset inventory
- offline geo-IP lookup for public/private address classification
- ATT&CK technique/tactic tagging for common event families
- candidate CVE context derived from known asset services

### 3) Better IDS / detection engineering
IDS rules are no longer only simple pattern strings. Rules now support Sigma-like logic fields such as:
- event types
- categories
- all/any keyword matching
- regex matching
- IOC matching
- asset criticality matching
- threshold-based detections
- confidence weighting
- ATT&CK technique/tactic metadata

### 4) Honest vulnerability scanning modes
Vulnerability scanning now supports two explicit operating modes:
- `evidence-driven`: analyst provides observed services/banner data and Sentinel-X maps them to CVEs
- `simulation`: when no live evidence is supplied, the scanner clearly labels the results as simulated

This prevents overclaiming and makes the project more credible.

### 5) Expanded investigation / forensics workflow
The project now includes:
- evidence records
- explicit chain-of-custody events
- incident timelines
- investigation artifact linking
- case overview aggregation

### 6) Added missing major cyber domains
New modules now include:
- asset inventory
- IAM monitoring
- endpoint telemetry
- cloud security findings
- phishing analysis
- SOAR playbooks and execution records
- platform audit logging

### 7) Better engineering maturity
This upgrade also adds:
- architecture diagram
- Dockerfile
- docker-compose
- CI workflow
- demo seed script
- environment template
- unit tests for normalization logic
- migration SQL for schema changes

---

## Architecture

See `docs/architecture.svg`.

Core flow:

1. Analyst or data source sends raw/syslog/JSON event.
2. Event is normalized into a common schema.
3. IOC, geo-IP, ATT&CK, CVE, and asset enrichment are applied.
4. Active IDS rules are evaluated.
5. Matching rules create alerts and detections.
6. High-confidence detections auto-create incidents.
7. Analysts investigate using forensics, phishing, IAM, endpoint, cloud, and SOAR modules.

---

## Key backend modules

### Event pipeline
- `server/security/pipeline.ts`
- `siem.ingestRawEvent`

### Vulnerability service
- `server/security/vulnerability.ts`
- `vulnerabilityScanning.runScan`

### Phishing analysis
- `server/security/phishing.ts`
- `phishing.analyze`

### SOAR orchestration
- `server/security/soar.ts`
- `soar.createPlaybook`
- `soar.execute`

### Demo dataset
- `server/security/demoData.ts`
- `siem.seedDemo`
- `scripts/seed-demo.ts`

---

## UI surfaces

### Existing modules retained
- Dashboard
- Incidents
- SIEM
- Threat Intel
- Vulnerability Scanner
- IDS
- Honeypot

### New analyst operations page
- `/operations`

This page exposes:
- pipeline ingestion
- asset registration
- IAM telemetry
- endpoint telemetry
- cloud findings
- phishing analysis
- SOAR playbooks and execution

---

## Database changes

Schema updates are defined in:
- `drizzle/schema.ts`
- `drizzle/0002_major_upgrade.sql`

New tables:
- `assets`
- `forensics_custody_events`
- `investigation_artifacts`
- `iam_events`
- `endpoint_telemetry`
- `cloud_findings`
- `phishing_analyses`
- `soar_playbooks`
- `soar_executions`
- `platform_audit_logs`

Extended tables:
- `security_events`
- `vulnerability_scans`
- `ids_rules`
- `ids_detections`
- `forensics_evidence`

---

## Local development

### 1. Install dependencies
Use the package manager defined in the repo.

### 2. Configure environment
Copy `.env.example` to `.env` and provide values.

### 3. Run migrations
Use the existing Drizzle migration flow.

### 4. Start the app
```bash
npm run dev
```

---

## Useful scripts

```bash
npm run dev
npm run build
npm run start
npm run test
npm run check
npm run seed:demo
```

---

## Demo workflow

1. Create an asset for `web-01.prod.internal`
2. Add a malicious IOC for `91.240.118.12`
3. Create or seed a Sigma-like SSH brute-force rule
4. Ingest repeated syslog authentication failures
5. Observe:
   - enriched event
   - IDS detection
   - generated alert
   - auto-created incident
6. Execute a SOAR playbook against the incident
7. Add evidence and custody events to the incident case

---

## Security design notes

This is still a portfolio/demo platform, not a production SOC product. Important boundaries:
- Geo-IP uses offline deterministic logic, not a commercial feed
- Vulnerability scanning is only evidence-driven or simulated, not a full network scanner
- SOAR actions are simulated and recorded, not destructive live response actions
- The current auth model is lightweight and should be hardened before real deployment

---

## Recommended next steps

For an even stronger senior-level version, add:
- true external intel feed ingestion (STIX/TAXII or MISP)
- live parser integrations for Suricata/Zeek/Windows Event logs
- stronger RBAC with analyst / lead / admin roles
- Sigma/YARA importers
- notification hooks (Slack/Teams/email)
- asset-to-vulnerability correlation views
- analyst search / hunting UI
- multi-tenant data separation

---

## Current implementation note

I made the code and repo changes directly in the project structure. I could not validate the full Node build inside this environment because package installation was unavailable here, so you should run:

```bash
npm install
npm run check
npm run test
npm run build
```

in your local machine or CI after pulling these changes.
