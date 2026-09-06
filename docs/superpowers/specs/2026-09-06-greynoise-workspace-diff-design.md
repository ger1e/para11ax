# GreyNoise Workspace Diff design

The approved design extends the existing GreyNoise Swarm specialist surface rather than creating a new subsystem.

The shell adds `swarm diff --query <GNQL>` with optional `--source`, `--target`, `--mode`, `--size`, and `--next-token` flags. Only the documented aliases `personal`, `community`, and `greynoise` are accepted. Defaults are `personal` to `greynoise`, `source-only`, size 10.

The same-origin authenticated PARA11AX gateway maps the command to the fixed GreyNoise endpoint `POST /v3/workspaces/diff`, forwards the API key only server-side, rejects redirects, sends bounded JSON, caps and sanitizes the JSON response, and preserves existing normalized error semantics.

Modes map to the vendor booleans without exposing arbitrary combinations: `source-only` sets `ips_from_source=true`; `both` sets `require_both_workspaces=true`; `all` leaves both false.

Successful diff output is read-only GreyNoise operator context and may be explicitly captured with `investigation capture operator`. It does not automatically create or mutate Evidence v2 evidence, correlation, maliciousness, ATT&CK mappings, or analyst disposition.
