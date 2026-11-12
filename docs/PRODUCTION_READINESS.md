# H4 TrustVerify — Production-readiness plan

Created by **Chris Cruz — @h4ckd4d**.

Implemented for demonstration: tenant filtering, admin/editor/viewer API keys (including SHA-256 digests), audit pagination, two-person approval checks and cancellation by creator/admin.

Generate strong random credentials and put only their SHA-256 digests under `key_sha256` in JSON `H4_TENANTS`. Legacy raw `key` works only for compatibility and should not be used for customer data.

Production work: OIDC/SSO and true user verification; transactional concurrency controls for approvals; out-of-band challenge verification; signatures and evidence retention; DB migrations, distributed idempotency and queues; quotas/rate limits, payment integration, legal review, monitoring, disaster recovery and load tests. No automatic fraud detection is claimed.
