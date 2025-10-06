# Floater Containment Protocol

## Purpose
The floater branch acts as a **sovereign raft** in the deployment lineage.  
It provides a buffer layer for experimental or unanchored logic before integration into mainline branches.

## Current Rules
- **Branch Name:** `floater-containment`
- **Discipline:** No direct merges to `main` allowed.
- **Buffer Logic:** Floater commits must be reviewed and staged before integration.
- **Secrets & Variables:** Explicitly declared; no implicit inheritance.

## Symbolic Echo
- The floater is a **raft**: it carries unanchored work safely until it can dock into mainline.
- Every floater commit is logged as a **lineage echo** for diagnostic improvement.

## Workflow Integration
- **verify-dialect.yml** ensures floater manifests are clean.
- **dialect-staging.yml** validates floater rules before merge.
- **ritual-deploy.yml** blocks deploys if floater logic is unsealed.

## Strategic Echo
The floater protocol ensures that unanchored or experimental work does not destabilize sovereign lineage.  
It is both a **safety buffer** and a **symbolic raft** for disciplined integration.
