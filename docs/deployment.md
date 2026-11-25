# Deployment

**Status: not deployed.** No hosting credentials were available in the development environment. Everything below was tested in CI, including the production image run under Render-like conditions (job `container under production conditions`). It has not been tested on Render itself.

The document has two parts that are not interchangeable: **Part A is the free plan** (what `render.yaml` describes, and what the participant chose in commit `d5b4f7a`). **Part B is a paid instance with a persistent disk.** If you follow Part A you never touch a disk path.

## How to read the claims
- **Tested in CI**: observed in a GitHub Actions run of the production image.
- **Render documentation / vendor statement**: taken from Render's public pages and not verified by running on Render. Cited where used.
- **Unverified assumption**: cannot be confirmed without a live Render service. Each one has a check below.

## What the image needs (both plans)
| Requirement | How it is met |
|---|---|
| Platform-assigned port | Uvicorn listens on `$PORT`. Render sets it (its default is 10000, per Render documentation); the image default is 8017. CI runs the image with `PORT=10000`. |
| Public HTTPS origin | Browser writes are accepted when `Origin` equals the request's `Host`, when it is listed in `NECROSHIELD_ALLOWED_ORIGINS`, or when it equals `RENDER_EXTERNAL_URL` (set by Render). No localhost assumption remains. |
| Client identity behind the proxy | `NECROSHIELD_PROXY_HOPS=1`: the rate-limit key is the right-most `X-Forwarded-For` entry. Each proxy appends the address it saw, so the right-most entry comes from the proxy nearest the app and a client cannot forge it ([MDN on X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)). Alternatively, `NECROSHIELD_CLIENT_IP_HEADER` names a header the proxy overwrites. |
| Non-root runtime | uid/gid 10001, no supplementary groups; checked in CI through `/proc/1/status`. |

<!-- free:start -->
## Part A: Render free plan (the blueprint in `render.yaml`)

### Deploy
1. Render dashboard → **New → Blueprint** → connect `leninathikam/necroshield` → apply. The blueprint asks for no values. It sets everything below itself.
2. When the deploy is live, run the post-deploy checks further down against the `onrender.com` URL.

### Configuration (all from `render.yaml`)
| Variable | Value | Why |
|---|---|---|
| `NECROSHIELD_DB` | `/tmp/necroshield.db` | The free plan has no persistent disk. The database is on the instance's temporary filesystem. |
| `NECROSHIELD_SEED_ON_START` | `1` | The database is empty on every start, so each boot recreates one verified pair per scenario. |
| `NECROSHIELD_PROXY_HOPS` | `1` | Key rate limits on each visitor, not on Render's proxy. See the proxy assumption below. |
| `NECROSHIELD_WRITE_LIMIT` | `30` | Per client, per minute. |
| `NECROSHIELD_BENCHMARK_LIMIT`, `_GLOBAL_WRITE_LIMIT`, `_LIVE_LIMIT`, `_MAX_PAIRS` | `4`, `600`, `3`, `1000` | See the abuse limits table. |

`NECROSHIELD_ALLOWED_ORIGINS` is deliberately not in the blueprint. A variable declared with `sync: false` makes Render prompt for a value when the blueprint is created, and the app does not need one: it accepts its own origin as same-origin and through `RENDER_EXTERNAL_URL`. Set `NECROSHIELD_ALLOWED_ORIGINS` in the dashboard only if you attach a custom domain, and then list that domain's origin.

CI starts the image with exactly these variables, read from `render.yaml` by `.github/scripts/render_env.py`, so a change to the blueprint is what CI tests.

### Cold starts, resets and reseeding
- **Spin down and cold start** (Render's public description of [free web services](https://render.com/docs/free), taken from search results; the page could not be fetched from the development environment, so re-read it before relying on the figures): a free web service spins down after 15 minutes without inbound traffic, and the next request waits for it to start again, which Render describes as taking about a minute. Free instances also share a monthly allowance of 750 instance hours. CI measures time from `docker run` to a healthy `/api/health` and fails above 60 seconds; this is the application's part only. Image pull and routing time on Render are not measured.
- **What is lost.** `/tmp/necroshield.db` belongs to one instance. Every spin-down, restart and redeploy replaces the instance, and the file with it. Visitor runs, approvals and any extra benchmark runs are gone.
- **Reseed.** On every start `NECROSHIELD_SEED_ON_START=1` creates the seven default pairs. After a restart the benchmark therefore shows seven pairs and nothing else. CI checks that a replacement instance starts with exactly seven pairs. Seeding the seven pairs measured 0.02 s locally and the app's peak memory after the judge flow measured 69 MB in CI, against the free plan's 512 MB.
- **Reset.** On the free plan, a reset is a restart: **Manual Deploy → Restart service** (or any deploy). There is no reset command to run. The Render Shell is not documented as available on free instances, so do not rely on it.
- **Auto-deploy.** Render deploys on each push to the linked branch by default. A deploy replaces the instance and wipes the database, and a push during judging would also reset the demo state. Turn auto-deploy off in the service settings before judging starts, and deploy manually when you intend to.
- **Before sharing the link.** Open the site once and wait for `/api/health` to return, so the first judge does not meet the cold start.

### Proxy assumption (unverified)
`NECROSHIELD_PROXY_HOPS=1` assumes Render puts exactly one proxy layer in front of the container and that it appends the client's address to `X-Forwarded-For`. This is an **unverified assumption**. If it is wrong, one of two things happens:
- Render has more than one layer, so the right-most entry is an internal proxy shared by all visitors. Every visitor then shares one rate-limit bucket (30 writes per minute for everyone) and judges see `429` responses.
- The header is absent, and the app falls back to the connecting socket, which is also shared.

Check it by hand after deploying: request `/api/client-key` from two different networks (for example your laptop and a phone on mobile data). The two `client_key_hash` values must differ. If they are equal, set `NECROSHIELD_PROXY_HOPS` to the number of proxy layers, or set `NECROSHIELD_CLIENT_IP_HEADER` to a header the platform overwrites, and check again.

### Post-deploy smoke test
```
python3 .github/scripts/container_smoke.py https://<service>.onrender.com
```
The script reads the deployment's configuration from `/api/health` and checks against that, so it passes with the real write limit of 30 and with any other limit. For an `https` or non-local address it runs in `proxied` mode. There it does not forge client addresses (a real proxy defeats that), probes the shared write limit last, and prints this machine's client key for the two-network check above. Use `--direct` or `--proxied` to force a mode. If seeding on start is off it seeds the benchmark first.

It checks the seeded benchmark, all pages, a same-origin run, cross-origin rejection, the MCP path, the evolution and theatre endpoints, that forged `X-Forwarded-For` entries do not create new clients, the per-client write limit, hostile bodies, and that live runs are refused. Run it again after a cold start. It writes about ten records and uses up this machine's write bucket for a minute, so wait before demonstrating from the same network.

Then run the browser suite against the deployment:
```
cd frontend && npm ci && npx playwright install chromium
PLAYWRIGHT_BASE_URL=https://<service>.onrender.com npx playwright test
```
<!-- free:end -->

<!-- paid:start -->
## Part B: paid instance with a persistent disk (not what `render.yaml` configures)
Choose this to keep history and avoid cold starts through **January 29, 2027** (the end of judging). It needs a paid instance type, because Render disks are not available on free instances.

1. Change `plan: free` to a paid plan in the blueprint, add a disk mounted at `/data`, and set `NECROSHIELD_DB=/data/necroshield.db`.
2. The entrypoint starts as root only to `chown` the mounted disk to uid 10001, then drops privileges (`scripts/docker_entrypoint.py`). CI tests this with a root-owned mount and a restart, and checks that history survives.
3. Run the same post-deploy smoke test as in Part A.

**Reset** (removes all stored runs, keeps the service running):
```
# Render → service → Shell
python -m necroshield reset-store --db /data/necroshield.db --yes
```
Then trigger **Manual Deploy → Restart** to reseed, or press **Run benchmark** in Benchmark Studio. History otherwise survives restarts and deploys.
<!-- paid:end -->

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

## Other notes
- Render restarts a service whose `/api/health` check fails.
- Leave the live-model variables unset on the public service.
