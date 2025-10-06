# Meta Audit Dashboard

## Purpose
The Meta Audit Dashboard aggregates lineage echoes from all workflows in `.github/workflows`.

## Active Workflows
- checksum-verify → Integrity baseline
- symbolic-review → PR review discipline
- verify-dialect → Dialect manifest verification
- dialect-staging → Buffer branch validation
- ritual-deploy → Deployment gate
- meta-audit → Aggregation of lineage echoes
- Security scans → Anchore, APIsec, Bandit, CodeQL, Semgrep, Snyk, SonarQube

## Audit Log
- Each workflow run appends its status to `meta-audit.txt`.
- This file is reviewed during the `meta-audit.yml` job.

## Strategic Echo
The dashboard ensures sovereign authorship by making lineage echoes visible and auditable.
