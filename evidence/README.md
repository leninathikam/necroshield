# Local release evidence

The initial repository was empty. This release is a working local deterministic
fixture arena, not a real-model evaluation or completed hackathon submission.
Dependency/runtime versions are recorded in [environment.json](environment.json).

## November 16 release verification

The command-center styles were split into twelve files with the original rules
in their original order. The production build identified an advisory affecting
the October lockfile. Updating Next.js from 16.4.3 to 16.4.6 resolved it. The
patched Webpack production build passed, and `npm audit` reported zero known
advisories for the resulting frontend lockfile.

With Python 3.14.3 and a fresh PostgreSQL 17.11 cluster on loopback, the full
backend suite passed **53/53 in 50.11 seconds**, including the opt-in PostgreSQL
migration, evidence round trip, and database-enforced read-only transaction test.
The only warning came from Starlette's TestClient dependency. The cluster used a
random test password and was stopped and removed afterward. To reproduce, set
`NECROSHIELD_TEST_DATABASE_URL` to a disposable PostgreSQL database and run
`python manage.py test`. The standalone document-injection evidence check passed
again. Node.js 22.13.1 was used for the November frontend checks. All four
Playwright tests passed against the patched release in 1.5 minutes, including
desktop export, registry and archive navigation, a live benchmark, and mobile
keyboard navigation.

## October 30 executed checks

- `python manage.py test`: **52 passed, 1 skipped**, exit 0; **21.13 seconds** for
  pytest, followed by a passing `tsc --noEmit`. The skipped test requires a real
  PostgreSQL service. One upstream Starlette/httpx TestClient deprecation warning
  was emitted; there were no application test failures.
- Final frontend `npm run build`: **passed**, Next.js 16.4.3 Webpack production
  compilation, types, static page generation, and trace packaging.
- Final `npm run test:e2e`: **4/4 passed**, real API/browser workflows, about 2.3
  minutes. Subsequent desktop/mobile screenshot recaptures each passed. These
  recaptures are not added to the four-test acceptance count.
- `python .kiro/scripts/validate_config.py`: **passed** for the documented local
  subset. Both fixed hook commands were also manually invoked and passed. No
  official Kiro runtime validation or Kiro event execution is claimed.
- `python manage.py dev`: **smoke-tested**; `/api/health` returned HTTP 200 with
  SQLite and synthetic-fixture mode; the dashboard returned HTTP 200 on port
  3017. Both owned services were stopped afterward, confirmed by closed ports.
- `docker compose config --quiet`: **passed** using an inert configuration-only
  password. No PostgreSQL server was started; runtime integration remains skipped.

The first canonical launcher attempt exposed a missing pytest-parent-directory
setup step: 32 tests passed, 17 fixture setups errored, and 1 was skipped. The
launcher was fixed to create the parent, then the exact documented command passed
all 52 tests above. Earlier restricted temporary-directory and concurrent
Next.js-generated-type failures are described in the phase reports; they are not
hidden or counted as successful application checks.

## Actual benchmark

`python manage.py benchmark` executed fresh isolated pairs from the final source
and produced [benchmark.json](benchmark.json). Benchmark ID:
`bd8bf1f2-2e13-4e91-b86e-704ea457b898`, timestamp
`2026-10-30T21:07:31.790186Z`.

- Six attacks: **6/6 baseline effects**, **0/6 protected effects**.
- Seven legitimate tasks: **7/7 protected completions**.
- **6** denied calls, **0/14** legitimate calls falsely denied.
- **14,017.707 ms** total measured benchmark latency before database commit.
- Provider cost: **null**, because no provider/model was called.

Every exported pair in that artifact passed the standalone verifier, independently
of application imports. The saved [document-injection sample](document-injection.json)
is from that exact benchmark:

```text
python scripts/verify_evidence.py evidence/document-injection.json
```

These rates describe intentionally vulnerable finite fixtures and default-deny
enforcement. They cannot be generalized to stochastic LLMs. Hashes verify internal
integrity/consistency relative to retained digests, not authorship or notarization.

## Phase reports

- [Phase 1: vertical slice](phase-1.md)
- [Phase 2: policy and forensics](phase-2.md)
- [Phase 3: replay and benchmark](phase-3.md)
- [Phase 4: interface and broader fixtures](phase-4.md)
- [Phase 5: independent review and remaining gates](phase-5.md)

See [independent review](../docs/security-review.md) for five resolved findings and
targeted regression evidence. See [the Kiro log](../docs/kiro-development.md) for
the explicit distinction between prepared configuration and genuine Kiro work.

## Unverified prerequisites

Genuine Kiro contributions,
hosted authenticated deployment, external testing, personal eligibility, and the
public demo/submission remain outstanding. The user chose to continue locally
and arrange Kiro later. No prize or submission eligibility is guaranteed.
