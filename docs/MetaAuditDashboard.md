# Meta Audit Dashboard

## Purpose
The Meta Audit Dashboard aggregates lineage echoes from all workflows in `.github/workflows` and cross‑links them to visual lineage artifacts in `/flowcharts`.

---

## 🌀 Workflow Gates Overview

| Discipline          | Workflow(s)            | Purpose / Gate Role                          | Flowchart Link |
|---------------------|------------------------|----------------------------------------------|----------------|
| **Integrity**       | checksum‑verify        | Ensures baseline integrity via checksum logs | [lineage-gates.png](../flowcharts/lineage-gates.png) |
| **Dialect**         | verify‑dialect         | Validates dialect manifests (TODO‑free)      | [dialect-staging-flow.png](../flowcharts/dialect-staging-flow.png) |
|                     | dialect‑staging        | Enforces buffer raft staging discipline      | [dialect-staging-flow.png](../flowcharts/dialect-staging-flow.png) |
| **Review**          | symbolic‑review        | PR review discipline, enforces sovereign authorship | [lineage-gates.png](../flowcharts/lineage-gates.png) |
| **Deployment**      | ritual‑deploy          | Seals merge gates, triggers deployment       | [lineage-gates.png](../flowcharts/lineage-gates.png) |
| **Meta‑Audit**      | meta‑audit             | Aggregates lineage echoes across workflows   | [lineage-gates.png](../flowcharts/lineage-gates.png) |
| **Security Scans**  | Anchore, APIsec, Bandit, CodeQL, Semgrep, Snyk, SonarQube | Multi‑layer security verification | [lineage-gates.png](../flowcharts/lineage-gates.png) |
| **Floater**         | floater‑containment (branch discipline) | Buffer raft for unanchored work | [floater-containment.png](../flowcharts/floater-containment.png) |

---

## 📜 Audit Log
- Each workflow run appends its status to `meta-audit.txt`.  
- This file is reviewed during the `meta-audit.yml` job.  
- Visual lineage artifacts provide diagrammatic confirmation of gate discipline.  

---

## ⚖️ Strategic Echo
The Meta Audit Dashboard is the **control room** of the forge:  
- **Textual** → workflow purpose, audit logs, covenant rules.  
- **Visual** → lineage diagrams for integrity, dialect staging, floater containment.  
- **Sovereign Loop** → Root → Docs → Flowcharts → Workflows → back to Root.  
