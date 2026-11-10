# app-safe

Correct versions of the patterns that `grep_patterns.sh` checks at block level (Go auth middleware, FastAPI / Flask endpoints, Firebase Cloud Functions, Express routes). `tests/run_tests.sh` asserts that **none** of those checks fire here (false-positive guard).
