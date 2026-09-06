# GreyNoise Workspace Diff mode mapping

PARA11AX exposes one mutually exclusive mode value so callers cannot construct ambiguous boolean combinations:

- `source-only` -> `ips_from_source=true`, `require_both_workspaces=false`
- `both` -> `ips_from_source=false`, `require_both_workspaces=true`
- `all` -> `ips_from_source=false`, `require_both_workspaces=false`
