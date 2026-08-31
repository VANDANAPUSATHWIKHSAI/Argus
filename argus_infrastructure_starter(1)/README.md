# Argus — Infrastructure Layer starter

## The rule
Everyone codes against `infrastructure/schemas.py` -- the `Evidence`, `CaseSession`,
`CustodyLogEntry`, and `AuditLogEntry` models. If a field is missing for what you
need, add it to `schemas.py` and tell the team in the group chat -- don't invent
your own shape for evidence data in your own file.

## Who owns what today

| Person | File | Stage |
|---|---|---|
| 1 | `infrastructure/upload/intake.py` | Evidence Upload |
| 2 | `infrastructure/sandbox/validate.py` | Sandboxed Intake Validation *(hardest -- pair up if you finish early)* |
| 3 | `infrastructure/integrity/hash_encrypt.py` | SHA-256 Hash + Encrypt |
| 4 | `infrastructure/custody/metadata_custody.py` | Metadata Extraction + Chain of Custody |
| 5 | `infrastructure/storage/repository.py` | Case ID/Session Setup + Original Evidence Repository + Audit Logging |

Each file has a `TODO` docstring explaining exactly what goes in and what comes
out, plus a commented-out example of what you're building toward. Delete the
`raise NotImplementedError` line once you've actually implemented the function.

## How evidence flows

```
raw bytes
   -> upload_evidence()              [Person 1]   status: UPLOADED
   -> sandbox_validate()             [Person 2]   status: SANDBOXED (or VALIDATION_FAILED -- stop)
   -> hash_and_encrypt()             [Person 3]   status: HASHED
   -> extract_metadata_and_log_custody() [Person 4]  status: METADATA_EXTRACTED
   -> store_evidence()               [Person 5]   status: STORED  <- Infrastructure Layer done
```

`infrastructure/pipeline.py` chains all five in order -- that's how we test the
whole thing end-to-end, not just each piece in isolation.

## Today's actual goal
Not "5 files pushed to GitHub." The real bar is:

```
python -m infrastructure.pipeline
```

...runs without errors and prints `[DONE]` with a real hash and repository
path. If your own function works standalone but breaks when chained to the
next person's, that's the thing to fix before end of day -- ping them
immediately, don't wait for a big end-of-day merge to discover it.

## Local databases (MinIO, PostgreSQL, Qdrant, Neo4j)

Everyone runs the SAME setup locally via Docker Compose -- what's in git is
the config/schema, never the actual data:

```
cp .env.example .env        # fill in your own local passwords
docker compose up -d        # starts all 4 services
```

- MinIO console: http://localhost:9001
- Postgres: localhost:5432 (schema auto-loads from seed/postgres_init.sql
  on first run)
- Qdrant: http://localhost:6333/dashboard
- Neo4j browser: http://localhost:7474

To wipe your local data and start fresh: `docker compose down -v`

**What goes in git:** `docker-compose.yml`, `seed/postgres_init.sql`,
`.env.example`, `.gitignore` -- these let anyone reproduce an identical
empty environment with one command.

**What does NOT go in git:** the actual database volumes, real evidence
files, or your real `.env` with real passwords. `.gitignore` is already
set up to block these -- don't `git add -f` around it.

## Workflow
1. Everyone works on their own branch: `git checkout -b infra/<your-name>`
2. Commit small and often -- not one giant commit at 6pm
3. Mid-afternoon: quick sync, specifically to catch interface mismatches early
   (e.g. "I'm passing a hex string hash, are you expecting bytes?")
4. End of day: one person (today's integration owner) merges branches into a
   `staging` branch one at a time, running `pipeline.py` after each merge
