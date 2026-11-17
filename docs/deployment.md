# Deployment and operational boundaries

The verified target for this release is a local desktop with a loopback FastAPI
service and Next.js dashboard. A hosted build is not claimed by a passing local
build. Sites hosting runs Cloudflare Workers; the requested Python FastAPI and
PostgreSQL architecture cannot be deployed there as a self-contained Site. A
static dashboard pointing at a visitor's localhost would not be a working hosted
application, so that is not shipped as a substitute.

## Optional local PostgreSQL

1. Start Docker Desktop, copy `.env.example` to `.env`, and set a local password.
2. Run `docker compose up -d database` from the root.
3. Set `DATABASE_URL` in the backend process environment using the SQLAlchemy
   `postgresql+psycopg://` URL. The example `.env` is not automatically loaded into
   the Python process. In PowerShell:

   ```powershell
   $env:DATABASE_URL = 'postgresql+psycopg://necroshield:YOUR_LOCAL_PASSWORD@127.0.0.1:5432/necroshield'
   ```

4. Apply migrations from `backend/` with `.venv/Scripts/python -m alembic upgrade head`
   on Windows or `.venv/bin/python -m alembic upgrade head` on Unix.
5. Run the application. For the integration check, set
   `NECROSHIELD_TEST_DATABASE_URL` to a separate disposable database and run
   `python manage.py test` from the repository root. The test applies migrations
   and writes a synthetic run.

The Compose service restricts the database port to loopback. Its resource limits
do not constitute a safe sandbox for hostile tools. The database contains only
synthetic fixtures. Docker was installed but its daemon was unavailable during
initial development. The November 16 integration run used native PostgreSQL
17.11 on loopback. The Compose deployment itself still needs runtime verification.

## Before a public demo

Choose infrastructure that supports a Python service and PostgreSQL. Run the
frontend with `npm run build` / `npm start`, and the backend under a process
supervisor. Configure server-side `BACKEND_URL` to the private backend. Keep the
browser on one origin; never expose database credentials through `NEXT_PUBLIC_`
variables. Enforce access and request budgets at the reverse proxy, TLS, an
authenticated judge account, CSRF/origin controls, logging and retention limits.

Use a separate unprivileged execution worker, no outbound networking, hard time,
memory, and process budgets, read-only filesystems, and stronger VM isolation
before introducing untrusted executable tools. Do not mount Docker sockets or
host credentials. The current deterministic fixtures do not authorize broadening
those capabilities.

Record the exact source commit, migration revision, dependency locks, platform,
URL, health response, benchmark digest, external tester feedback, and rollback
procedure in a new evidence report. Only then label that deployment tested.

## Submission handoff

The public repository and judge URL must exist and work before making the video.
Capture a real attack, its baseline effect, protected pre-execution denial, valid
task result, policy explanation, and downloaded evidence. Keep the video below
three minutes. Show only behavior that can be reproduced with the documented
commands. Add genuine Kiro contribution records after running Kiro, then recheck
the official rules and submit through Devpost.
