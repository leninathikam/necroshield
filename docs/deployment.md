# Deployment

**Status: not deployed.** No hosting credentials were available in the development environment. Everything below was tested in CI. That includes running the production image under Render-like conditions (job `container under production conditions`). It has not been tested on Render itself.

## What the image needs
| Requirement | How it is met |
|---|---|
| Platform-assigned port | Uvicorn listens on `$PORT` (Render sets it, normally 10000; the default is 8017). CI runs the image with `PORT=10000`. |
| Persistent SQLite under `/data` | `NECROSHIELD_DB=/data/necroshield.db`. The entrypoint starts as root only to `chown` the mounted disk to uid 10001, then drops privileges (`scripts/docker_entrypoint.py`). CI mounts a root-owned directory, restarts the container, and checks that the history survives. |
| Public HTTPS origin | Browser writes are accepted when `Origin` equals the request's `Host`, or when it is listed in `NECROSHIELD_ALLOWED_ORIGINS`, or when it equals `RENDER_EXTERNAL_URL` (set by Render). No localhost assumption remains. |
| Client identity behind the proxy | `NECROSHIELD_PROXY_HOPS=1`: the rate-limit key is the right-most `X-Forwarded-For` entry, which the proxy adds and a client cannot forge. Alternatively, `NECROSHIELD_CLIENT_IP_HEADER` names a header the proxy overwrites. |
| Non-root runtime | uid/gid 10001, no supplementary groups; checked in CI through `/proc/1/status`. |

## Render (blueprint in `render.yaml`)
The blueprint uses the **free plan with the database in `/tmp`**, as the participant chose in commit `d5b4f7a`:
1. Render dashboard → **New → Blueprint** → connect `leninathikam/necroshield` → apply. Leave `NECROSHIELD_ALLOWED_ORIGINS` empty. The public origin is accepted automatically, both as same-origin and through `RENDER_EXTERNAL_URL`.
2. When the deploy is live, run the post-deploy checks below against the `onrender.com` URL.

Free-plan consequences:
- The instance sleeps when idle, and the first visit after a sleep waits for it to start.
- `/tmp` is erased on every restart or sleep, so visitors' runs do not persist.
- `NECROSHIELD_SEED_ON_START=1` re-creates one verified pair per scenario on every boot, so the benchmark and every page always have data.
- CI runs this exact configuration (`free-plan configuration from render.yaml`).

To keep history and avoid cold starts through **January 29, 2027** (the end of judging), upgrade to a paid instance type, which disks require. Then:
- add a disk mounted at `/data`;
- set `NECROSHIELD_DB=/data/necroshield.db`.

The entrypoint takes ownership of a root-owned disk and then drops to uid 10001. CI tests this with a root-owned mount and a restart.

## Post-deploy checks (run against the public URL)
```
python3 .github/scripts/container_smoke.py https://<service>.onrender.com
```
This checks:
- the seeded benchmark;
- all seven pages;
- a same-origin run;
- that cross-origin writes are rejected;
- the MCP path;
- that forged `X-Forwarded-For` entries do not change the client key;
- per-client limits;
- that hostile bodies are rejected;
- that live runs are refused.

The per-client limit check assumes `NECROSHIELD_WRITE_LIMIT=5`. On the blueprint's limit of 30, expect that one assertion to fail and the rest to pass.

Then run the browser suite against the deployment:
```
cd frontend && npm ci && npx playwright install chromium
PLAYWRIGHT_BASE_URL=https://<service>.onrender.com npx playwright test
```

Also check the proxy assumption by hand. Two requests from different networks should return different `client_key_hash` values from `/api/client-key`. If every client gets the same hash, the proxy is not appending the address as expected. In that case, set `NECROSHIELD_CLIENT_IP_HEADER` to the header Render forwards (for example `cf-connecting-ip`) and recheck.

## Abuse limits for a public, no-login demo
Writes are unauthenticated on purpose, so judges need no account. These limits bound what an anonymous visitor can do:

| Control | Default (blueprint) | Effect |
|---|---|---|
| Per-client writes | 30/min | Bounds one visitor |
| Per-client benchmark runs | 4/min | Each run stores 7 pairs |
| Global writes | 600/min | Bounds total work across all clients |
| Per-client reads | 600/min | Each read re-verifies evidence |
| Body size | 256 KB, also enforced while streaming | |
| Retention | 1000 pairs (blueprint) | The oldest pairs are pruned; the newest default-policy pair per scenario is always kept, so the benchmark never empties |
| Live model runs | disabled | They need a provider and an operator token; never available to visitors |

Every request is limited to synthetic scenarios: there are no file, network, or process tools. Uploaded evidence is only parsed and verified, never executed or stored. Deeply nested or malformed JSON returns 400 or 422.

Residual risk: rate limits are per process and in memory, so a restart resets them. A distributed flood can still use the whole global budget and slow the demo; it cannot corrupt stored evidence. Render's own edge protection is the layer in front of this.

## Demo reset
Removes all stored runs, keeps the service running, and reseeds on the next restart:
```
# Render → service → Shell
python -m necroshield reset-store --db /data/necroshield.db --yes
```
Then trigger **Manual Deploy → Restart** to reseed the benchmark, or press **Run benchmark** in Benchmark Studio. On the free plan, a restart alone also resets the data, because `/tmp` is cleared. The Render Shell may not be available on free instances.

## Keeping it up through January 29, 2027
- The free plan stays reachable but sleeps when idle. A judge's first request waits for the instance to start. A paid instance avoids this.
- Render restarts the service when `/api/health` fails its health check.
- Keep `autoDeploy: true` only if `main` stays green. Every push runs the full CI.
- Leave the live-model variables unset on the public service.
