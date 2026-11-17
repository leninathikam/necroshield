import { test, expect } from "@playwright/test";

test("launches a real paired run, inspects a denial, and exports redacted evidence", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("API connected", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Attack arena." })).toBeVisible();
  await expect(page.getByText("The boundary is the experiment.")).toBeVisible();
  await page.getByLabel("SCENARIO", { exact: true }).selectOption("document-injection");
  const created = page.waitForResponse(response => response.url().endsWith("/api/runs") && response.request().method() === "POST");
  await page.getByRole("button", { name: "Launch paired run" }).click();
  const response = await created;
  expect(response.status()).toBe(201);
  const pair = await response.json();
  expect(pair.baseline.metrics.attack_success).toBe(true);
  expect(pair.protected.metrics.attack_success).toBe(false);
  expect(pair.protected.metrics.legitimate_task_completed).toBe(true);
  await expect(page.getByText("Attack effect observed", { exact: true })).toBeVisible();
  await expect(page.getByText("No attack effect", { exact: true })).toBeVisible();
  const inspector = page.getByRole("heading", { name: "Decision inspector" }).locator("..").locator("..");
  await expect(inspector.getByText("deny", { exact: true })).toBeVisible();
  await expect(inspector.getByRole("heading", { name: "sink.send" })).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: "Export redacted evidence" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe(`necroshield-${pair.id}.json`);
  const exportResponse = await page.request.get(`/api/runs/${pair.id}/export`);
  expect(exportResponse.status()).toBe(200);
  const exported = await exportResponse.text();
  expect(exported).not.toContain("SYNTHETIC-SECRET-NECRO-0001");
  await page.evaluate(() => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); window.scrollTo(0, 0); });
  await page.screenshot({ path: "test-results/arena-completed-viewport.png" });
  await page.screenshot({ path: "test-results/arena-completed.png", fullPage: true });
});

test("registry navigation and retained history use the API", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("API connected", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Scenario registry", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Scenario registry." })).toBeVisible();
  const response = await page.request.get("/api/scenarios");
  const scenarios = await response.json();
  await expect(page.getByRole("button", { name: "Open in arena" })).toHaveCount(scenarios.length);
  await page.getByRole("button", { name: "Open in arena" }).first().click();
  await expect(page.getByRole("heading", { name: "Attack arena." })).toBeVisible();
  await page.getByRole("button", { name: "Run archive", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Run archive." })).toBeVisible();
  const runsResponse = await page.request.get("/api/runs");
  const runs = await runsResponse.json();
  await expect(page.getByRole("button", { name: "Inspect", exact: true })).toHaveCount(runs.length);
  if (runs.length) {
    await page.getByRole("button", { name: "Inspect", exact: true }).first().click();
    await expect(page.getByRole("heading", { name: "Attack arena." })).toBeVisible();
    await expect(page.getByRole("link", { name: "Export redacted evidence" })).toBeVisible();
  }
});

test("benchmark displays measured registry results without asserting fabricated scores", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("API connected", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Benchmarks", exact: true }).click();
  await expect(page.getByText("No benchmark has been executed in this session.", { exact: false })).toBeVisible();
  const completion = page.waitForResponse(response => response.url().endsWith("/api/benchmarks") && response.request().method() === "POST");
  await page.getByRole("button", { name: "Run benchmark", exact: true }).click();
  const response = await completion;
  expect(response.status()).toBe(201);
  const benchmark = await response.json();
  await expect(page.getByText(`${benchmark.blocked_executions} executions`, { exact: true })).toBeVisible();
  await expect(page.getByText("Not measured · no model calls", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Reproducible result" })).toBeVisible();
});

test("mobile layout remains contained and navigation is keyboard accessible", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByText("API connected", { exact: true })).toBeVisible();
  const pageWidth = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, viewport: window.innerWidth }));
  expect(pageWidth.scroll).toBeLessThanOrEqual(pageWidth.viewport);
  await page.getByLabel("SCENARIO", { exact: true }).selectOption("document-injection");
  await page.getByRole("button", { name: "Launch paired run" }).click();
  await expect(page.getByText("No attack effect", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Launch paired run", exact: true })).toBeEnabled();
  const completedWidth = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, viewport: window.innerWidth }));
  expect(completedWidth.scroll).toBeLessThanOrEqual(completedWidth.viewport);
  await page.evaluate(() => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); window.scrollTo(0, 0); });
  await page.screenshot({ path: "test-results/arena-completed-mobile.png", fullPage: true });
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
  await page.getByRole("button", { name: "Scenario registry", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Scenario registry." })).toBeVisible();
  await page.screenshot({ path: "test-results/arena-mobile.png", fullPage: true });
});
