# GreyNoise Workspace Diff TDD gate

1. Commit shell/client and gateway tests before production implementation.
2. Open a draft PR and observe the new tests fail for the missing `diff` command/handler behavior.
3. Implement the minimum parser, client, gateway, executor/catalog, and documentation changes to satisfy the contract.
4. Run final Tooling smoke and CodeQL on the exact PR head.
5. Squash-merge with expected head SHA pinned, then verify fresh main CI and Vercel production identity.
