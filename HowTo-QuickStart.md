# How to Work with Echo‑Forge‑AI‑Integrity

## Quick Start
1. Clone the repository (private access required).
2. Review the [README.md](./README.md) for project overview.
3. Explore the [docs/](./docs) folder for detailed manifests.

## Key Docs
- [MetaAuditDashboard.md](./docs/MetaAuditDashboard.md) → Workflow audit dashboard
- [DialectManifest.md](./docs/DialectManifest.md) → Dialect rules and staging discipline
- [LicensePortfolio.md](./docs/LicensePortfolio.md) → Current MIT covenant + future license options

## Workflows
- All workflows live in `.github/workflows/`.
- Symbolic gates enforce integrity, dialect validation, review discipline, and deployment.

## Contribution Ritual
- Open a feature branch.
- Ensure dialect manifests are clean (no TODOs).
- Submit PR → symbolic review gate will enforce review.
- Merges to `main` trigger checksum verification and ritual deploy.

---

## Strategic Echo
This HOWTO is a light guide. For full lineage details, always consult the `/docs` layer.
