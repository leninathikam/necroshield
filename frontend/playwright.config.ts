import { defineConfig, devices } from "@playwright/test";

const PORT = 8017;
const BASE = `http://127.0.0.1:${PORT}`;

/** End-to-end tests run against the real FastAPI app serving the static frontend build.
 * Nothing is mocked: every assertion is about a run executed by the backend. */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: { baseURL: BASE, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command:
      `python -m uvicorn necroshield.api.app:app_from_env --factory --host 127.0.0.1 --port ${PORT}`,
    cwd: "../backend",
    url: `${BASE}/api/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      NECROSHIELD_STATIC: "../frontend/out",
      NECROSHIELD_DB: process.env.E2E_DB ?? "/tmp/necroshield-e2e.db",
      NECROSHIELD_ALLOWED_ORIGINS: BASE,
      NECROSHIELD_WRITE_LIMIT: "1000",
    },
  },
});
