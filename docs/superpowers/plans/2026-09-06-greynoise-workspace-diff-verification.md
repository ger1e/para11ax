# GreyNoise Workspace Diff verification criteria

Completion requires:

- test-only RED observed on the feature branch;
- final PR head Tooling smoke success;
- final PR head CodeQL success;
- no unresolved review threads;
- squash merge with expected head SHA;
- fresh post-merge Tooling smoke and CodeQL on exact main SHA;
- Vercel production READY on the same main SHA;
- public root health and Swarm route fail-closed smoke checks.
