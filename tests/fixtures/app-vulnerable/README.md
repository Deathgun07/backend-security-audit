# app-vulnerable

**Intentionally vulnerable** application used as the target of the skill tests. It covers the 12 supported stacks. Never deploy it.

The `.env` file (with fake secrets) is generated on the fly by `tests/run_tests.sh`, so that no string resembling a real key is committed (GitHub push protection would block it).
