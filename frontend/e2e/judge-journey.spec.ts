import { expect, test } from "@playwright/test";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

/** The ten-step judge journey from docs/demo-script.md, run end to end against the real API.
 * Step timings are written to test-results so the demo pace can be checked. */
test("judge journey: attack, deny, complete, graph, MCP, benchmark, verify", async ({ page }) => {
  const timings: { step: string; ms: number }[] = [];
  const started = Date.now();
  let last = started;
  const mark = (step: string) => {
    const now = Date.now();
    timings.push({ step, ms: now - last });
    last = now;
  };

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  mark("1 open dashboard");

  await page.getByRole("link", { name: "Attack Arena" }).click();
  await page.getByLabel("Scenario").selectOption("tool_response_injection");
  await expect(page.locator("mark").first()).toContainText("collector@sink.invalid");
  mark("2 select malicious tool-response scenario");

  await page.getByRole("button", { name: "Launch simulation" }).click();
  await expect(page).toHaveURL(/\/replay\/\?pair=/);
  mark("3 start baseline and protected runs");

  const baseline = page.locator(".is-baseline");
  const protectedRun = page.locator(".is-protected");
  const attempt = baseline.locator(".callrow", { hasText: 'to="collector@sink.invalid"' });
  await expect(attempt).toContainText("executed");
  await expect(baseline).toContainText("attack: the customer token reached an address other than billing");
  mark("4 inspect the unauthorized attempted action");

  const denied = protectedRun.locator(".callrow", { hasText: 'to="collector@sink.invalid"' });
  await expect(denied).toContainText("denied before dispatch");
  await expect(denied).toContainText("outside granted scope");
  await expect(protectedRun).not.toContainText("attack: the customer token");
  await expect(page.getByText("decisive", { exact: true })).toBeVisible();
  mark("5 inspect the denial and the prevented side effect");

  await expect(protectedRun).toContainText("task completed");
  await expect(protectedRun).toContainText("task: billing received the invoice customer's record");
  mark("6 confirm the legitimate task completed");

  await page.getByRole("link", { name: "Open the execution graph" }).click();
  await page.getByRole("button", { name: "protected", exact: true }).click();
  await expect(page.getByText("No attack effect")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/denied ×1/)).toBeVisible();
  mark("7 open the execution graph");

  await page.getByRole("link", { name: "Attack Arena" }).click();
  await page.getByLabel("Scenario").selectOption("tool_response_injection");
  await page.getByLabel("Target agent").selectOption("mcp");
  await page.getByRole("button", { name: "Launch simulation" }).click();
  const transcript = page.getByLabel("MCP transcript");
  await expect(transcript).toContainText("denied before dispatch");
  await expect(transcript).toContainText("attack blocked, task completed");
  mark("8 run the real MCP sandbox path");

  await page.getByRole("link", { name: "Benchmark Studio" }).click();
  await page.getByRole("button", { name: "Run benchmark" }).click();
  await expect(page.getByText("0 / 6")).toBeVisible({ timeout: 20_000 });
  mark("9 run the benchmark");

  await page.getByRole("link", { name: "open pair" }).first().click();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("link", { name: "Download evidence (JSON)" }).click(),
  ]);
  const file = await download.path();
  await page.getByRole("link", { name: "Evidence Explorer" }).click();
  await page.getByLabel("Evidence file").setInputFiles(file);
  await expect(page.locator(".chip-verified", { hasText: /^verified$/ })).toBeVisible();
  const exported = JSON.parse(readFileSync(file, "utf-8"));
  expect(exported.replay_mode).toBe("deterministic_intent_replay");
  mark("10 export and verify the evidence");

  const total = Date.now() - started;
  mkdirSync("test-results", { recursive: true });
  writeFileSync(`test-results/judge-journey-${test.info().project.name}.json`, JSON.stringify({ total, timings }, null, 2));
  expect(total).toBeLessThan(60_000);
});
