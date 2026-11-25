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
1. Render dashboard → **New → Blueprint** → connect `leninathikam/necroshield` → apply.
2. The blueprint creates the Docker web service `necroshield` (plan `starter`) with a 1 GB disk at `/data`. Persistent disks require a paid instance type.
3. When the deploy is live, run the post-deploy checks below with the `onrender.com` URL.

Cost: one starter instance plus a 1 GB disk, kept running from deployment through **January 29, 2027** (the end of judging). Check Render's current pricing before choosing.

The free plan works without the disk, with two consequences:
- The service sleeps when idle and takes time to wake.
- Its filesystem is ephemeral.

`NECROSHIELD_SEED_ON_START=1` re-creates a verified benchmark on every boot, so pages are never empty, but visitors' runs are lost on restart.

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
| Retention | 5000 pairs | The oldest pairs are pruned; the newest default-policy pair per scenario is always kept, so the benchmark never empties |
| Live model runs | disabled | They need a provider and an operator token; never available to visitors |

Every request is limited to synthetic scenarios: there are no file, network, or process tools. Uploaded evidence is only parsed and verified, never executed or stored. Deeply nested or malformed JSON returns 400 or 422.

Residual risk: rate limits are per process and in memory, so a restart resets them. A distributed flood can still use the whole global budget and slow the demo; it cannot corrupt stored evidence. Render's own edge protection is the layer in front of this.

## Demo reset
Removes all stored runs, keeps the service running, and reseeds on the next restart:
```
# Render → service → Shell
python -m necroshield reset-store --db /data/necroshield.db --yes
```
Then trigger **Manual Deploy → Restart** to reseed the benchmark, or run `POST /api/benchmark` from the UI.

## Keeping it up through January 29, 2027
- Use a paid instance, so it does not sleep, with the disk attached.
- Render restarts the service when `/api/health` fails its health check.
- Keep `autoDeploy: true` only if `main` stays green. Every push runs the full CI.
- Leave the live-model variables unset on the public service.
