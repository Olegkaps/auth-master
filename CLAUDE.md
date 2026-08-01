# Development instructions — auth-master

The canonical agent instructions are in [AGENTS.md](AGENTS.md). They apply to
all contributors and tools working in this repository.

In particular:

- run all tests and infrastructure tasks through `make`;
- add automated Go tests for every feature or behavior change;
- add or update Playwright E2E coverage for every user-visible feature;
- regenerate Swagger artifacts with `make swagger` after API changes;
- run `make check` before merge and `make test` for full verification.
