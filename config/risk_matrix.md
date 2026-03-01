# Cloud Run Security Risk Reference Matrix

This file is the **single source of truth** for Cloud Run risk classification logic.
It is read at runtime by `agent/orchestrator.py` and used as context for Gemini.
Update this file to evolve risk standards — no code changes required.

---

## Risk Categories

| Category | Conditions | Risk Level | Priority |
|---|---|---|---|
| Critical: Exposed & Abandoned | ingress=all + unauthenticated=True + traffic=0 | Critical | P0 — Immediate action |
| High: Public Direct Access | ingress=all + unauthenticated=True + traffic>0 | High | P1 — Fix within sprint |
| Medium: Identity Leakage | ingress=all + unauthenticated=False + default SA | Medium | P2 — Fix within quarter |
| Medium: LB Bypass Risk | ingress=all + unauthenticated=False | Medium | P2 — Fix within quarter |
| Low: Shielded | ingress=internal-and-cloud-load-balancing + authenticated | Low | P3 — Review only |
| Minimal: Zero Trust | ingress=internal + custom SA + VPC Service Controls | Minimal | No action needed |

---

## Risk Scoring Hierarchy

Evaluate dimensions in this exact order. **First matching category wins.**

### Dimension 1: Network Perimeter (Ingress)

- **`ingress=all`** → Immediate risk flag. Service is directly reachable from the public internet, bypassing any Load Balancer or WAF.
- **`ingress=internal-and-cloud-load-balancing`** → Traffic must flow through a Load Balancer. Verify Cloud Armor policy is attached.
- **`ingress=internal`** → Service is only reachable from within the VPC. Verify a VPC Connector is attached.

### Dimension 2: Access Control (Authentication)

- **`unauthenticated=True`** → Service accepts requests without any identity token. If this is not the explicit business requirement (e.g. a public website), flag as Critical.
- **`unauthenticated=False`** → IAM authentication required. Verify the invoker has `roles/run.invoker` scoped correctly.

### Dimension 3: Identity (Service Account)

- **Red Flag:** `{PROJECT_NUMBER}-compute@developer.gserviceaccount.com`
  The default Compute SA typically has `Editor` permissions. If the container is breached, the attacker gains broad project access.
- **Best Practice:** A dedicated per-service custom SA e.g. `cr-service-name@project.iam.gserviceaccount.com` with only the permissions that service needs (least privilege).

---

## Recommended "Safe" Configuration Baseline

| Dimension | Required Value |
|---|---|
| Ingress | `internal` or `internal-and-cloud-load-balancing` |
| Authentication | Authenticated only (IAM or IAP) |
| Identity | Dedicated custom service account (non-default) |
| Traffic | Active. Zero traffic only acceptable for internal services. |

---

## LLM Instructions Per Risk Category

### Critical: Exposed & Abandoned
Flag as **"Highest Priority."** Abandoned public endpoints are "shadow IT" and prime targets for exploitation or subdomain takeover attacks. Immediate remediation required.

### High: Public Direct Access
Flag as **"Architecture Violation."** Services must be placed behind a Load Balancer with Cloud Armor to mitigate DDoS and OWASP Top 10 risks. Active traffic does not justify public exposure.

### Medium: Identity Leakage
Even if authentication is required, `ingress=all` makes the service discoverable from the internet. The default Compute SA provides excessive permissions if the container is breached. Replace with a custom SA.

### Medium: LB Bypass Risk
**Critical Logic Point:** If a Load Balancer exists but ingress is still set to `all`, attackers can bypass the LB (and its WAF/Cloud Armor) by hitting the `.run.app` URL directly. Set ingress to `internal-and-cloud-load-balancing`.

### Low: Shielded
This is the **"Enterprise Standard."** Traffic is forced through the LB (enabling WAF protection) and requires IAM/OIDC identity. Recommend reviewing Cloud Armor policy completeness.

### Minimal: Zero Trust
This is the **"Gold Standard."** The service is invisible to the internet and operates with least privilege via a dedicated Service Account. No remediation needed — monitor for configuration drift.
