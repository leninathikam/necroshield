import { defineConfig, devices } from "@playwright/test";
import path from "node:path";

const backendDir = path.resolve(__dirname, "../backend");
const python = path.join(backendDir, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
const backendPort = process.env.E2E_BACKEND_PORT || "8017";
const frontendPort = process.env.E2E_FRONTEND_PORT || "3017";
const backendUrl = `http://127.0.0.1:${backendPort}`;
const frontendUrl = `http://127.0.0.1:${frontendPort}`;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never" }]],
  use: { baseURL: frontendUrl, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `"${python}" -m uvicorn necroshield.main:app --host 127.0.0.1 --port ${backendPort}`,
      cwd: backendDir,
      url: `${backendUrl}/api/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: { NECROSHIELD_DATA_DIR: "data-e2e", NECROSHIELD_FRONTEND_ORIGIN: frontendUrl },
    },
    {
      command: `npm run dev -- --port ${frontendPort}`,
      url: frontendUrl,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      env: { BACKEND_URL: backendUrl, NEXT_TELEMETRY_DISABLED: "1" },
    },
  ],
});
