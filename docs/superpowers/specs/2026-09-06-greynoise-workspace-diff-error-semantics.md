# GreyNoise Workspace Diff error semantics

Local validation failures return bounded 400 errors before egress. GreyNoise 400 remains a query rejection, 401/403 remain authentication-or-entitlement failures, 429 remains rate limiting, and other upstream/transport/timeout/oversize failures retain the existing Swarm normalized error families. Operational failure is never negative threat evidence.
