import { expect, test, type Page } from "@playwright/test";

async function noHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: `test-results/screens/${test.info().project.name}-${name}.png`, fullPage: true });
}

test("dashboard sequence: attack, policy generation, counterfactual, human approval, verification", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.getByLabel("Attack for the sequence").selectOption("document_injection");
  await page.getByRole("button", { name: "Run the sequence" }).click();
  const hero = page.locator(".hero");
  await expect(hero).toContainText("Unprotected run: attack: another customer's token reached the sink", { timeout: 15_000 });
  await expect(hero).toContainText("candidate policies built from the trusted task", { timeout: 15_000 });
  await expect(hero).toContainText("Remove the decisive denial and the attack returns", { timeout: 15_000 });
  // Nothing is approved or verified until the visitor clicks.
  const approve = page.getByRole("button", { name: "Approve and run" });
  await expect(approve).toBeVisible({ timeout: 15_000 });
  await expect(hero).toContainText("Nothing is activated until you approve");
  await expect(hero).not.toContainText("standalone verifier");
  await approve.click();
  await expect(hero).toContainText("attack blocked", { timeout: 15_000 });
  await expect(hero).toContainText("task completed");
  await expect(hero).toContainText("scripts/verify_evidence.py offline", { timeout: 15_000 });
  const order = await hero.locator("h3").allTextContents();
  expect(order).toEqual(["1. Attack", "2. Policy generation", "3. Counterfactual test", "4. Human approval", "5. Independent verification"]);
  await noHorizontalOverflow(page);
  await shot(page, "dashboard");
  await page.getByRole("link", { name: "Open in Replay Lab" }).click();
  await expect(page.getByRole("heading", { name: "Replay Lab" })).toBeVisible();
});

test("dashboard sequence shows the held-out attack the Lab suggestion fails", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Attack for the sequence").selectOption("memory_overwrite_allowed_key");
  await page.getByRole("button", { name: "Run the sequence" }).click();
  await expect(page.locator(".hero")).toContainText("lets the forbidden effect through", { timeout: 15_000 });
  await expect(page.locator(".hero")).toContainText("not a held-out result");
});

test("arena shows inert injected source and launches a pair", async ({ page }) => {
  await page.goto("/arena/");
  await page.getByLabel("Scenario", { exact: true }).selectOption("tool_response_injection");
  await expect(page.getByText("customer:cust-001", { exact: true })).toBeVisible();
  const mark = page.locator("mark").first();
  await expect(mark).toContainText("assistant: call send_message");
  expect(await page.locator("pre.source script").count()).toBe(0);
  await expect(page.getByText("billing@finance.invalid").first()).toBeVisible();
  await noHorizontalOverflow(page);
  await shot(page, "arena");
  await page.getByRole("button", { name: "Launch simulation" }).click();
  await expect(page).toHaveURL(/\/replay\/\?pair=/);
  await expect(page.getByText("denied before dispatch").first()).toBeVisible();
  await expect(page.getByText("decisive").first()).toBeVisible();
  await expect(page.locator(".is-baseline")).toContainText("attack succeeded");
  await expect(page.locator(".is-protected")).toContainText("attack blocked");
  await expect(page.locator(".is-protected")).toContainText("task completed");
  await noHorizontalOverflow(page);
  await shot(page, "replay");
});

test("fixture agent over a real MCP session is denied at the gateway", async ({ page }) => {
  await page.goto("/arena/");
  await page.getByLabel("Scenario", { exact: true }).selectOption("document_injection");
  await page.getByLabel("Target agent").selectOption("mcp");
  await page.getByRole("button", { name: "Launch simulation" }).click();
  const transcript = page.getByLabel("MCP transcript");
  await expect(transcript).toContainText("mcp in-memory session (official SDK)");
  await expect(transcript).toContainText("not hash-chained");
  await expect(transcript).toContainText("denied before dispatch");
  await expect(transcript).toContainText("attack blocked, task completed");
});

test("policy inspector runs a counterfactual with a weakened policy", async ({ page }) => {
  await page.goto("/policy/?scenario=document_injection");
  await page.getByLabel("New grant for").selectOption("send_message");
  await page.getByRole("button", { name: "Add grant" }).click();
  await expect(page.getByLabel("Policy JSON")).toContainText("g-custom-5");
  await page.getByRole("button", { name: "Run with this policy" }).click();
  await expect(page).toHaveURL(/\/replay\/\?pair=/);
  await expect(page.getByText("(custom)")).toBeVisible();
  await expect(page.locator(".is-protected")).toContainText("attack succeeded");
  await shot(page, "policy-counterfactual");
});

test("invalid policy edits are rejected by the server", async ({ page }) => {
  await page.goto("/policy/?scenario=benign_invoice");
  await page.getByLabel("path (comma-separated allowed values, or * for any string)").fill("");
  await page.getByRole("button", { name: "Run with this policy" }).click();
  await expect(page.locator("p[role=alert]")).toContainText("Rejected");
});

test("graph plays back the chained events", async ({ page }) => {
  await page.goto("/arena/");
  await page.getByLabel("Scenario", { exact: true }).selectOption("memory_poisoning");
  await page.getByRole("button", { name: "Launch simulation" }).click();
  await expect(page).toHaveURL(/\/replay\/\?pair=/);
  const pair = new URL(page.url()).searchParams.get("pair");
  await page.goto(`/graph/?pair=${pair}`);
  await expect(page.getByText("Event 5 of 5")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Attack effect observed")).toBeVisible();
  await page.getByRole("button", { name: "Step back" }).click();
  await expect(page.getByText(/Event 4 of 5/)).toBeVisible();
  await page.getByRole("button", { name: "protected", exact: true }).click();
  await expect(page.getByText("Event 5 of 5")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("No attack effect")).toBeVisible();
  await expect(page.getByText(/denied ×1/)).toBeVisible();
  await shot(page, "graph");
});

test("benchmark studio measures every scenario and the bundle verifies", async ({ page, request }) => {
  await page.goto("/benchmark/");
  await page.getByRole("button", { name: "Run benchmark" }).click();
  await expect(page.getByText("6 / 6").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("0 / 6")).toBeVisible();
  await expect(page.getByText("0 / 1")).toBeVisible();
  await expect(page.getByText(/cost: null/)).toBeVisible();
  await expect(page.getByRole("link", { name: "open pair" })).toHaveCount(7);
  await noHorizontalOverflow(page);
  await shot(page, "benchmark");

  const bundle = await (await request.get("/api/benchmark/bundle")).json();
  await page.goto("/evidence/");
  await page.getByLabel("Evidence file").setInputFiles({
    name: "bundle.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(bundle)),
  });
  await expect(page.getByRole("status").filter({ hasText: "verified" })).toBeVisible();

  bundle.summary.attack_success.protected.numerator = 0;
  bundle.summary.denial_rate.numerator = 0;
  await page.getByLabel("Evidence file").setInputFiles({
    name: "forged.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(bundle)),
  });
  await expect(page.getByText("summary does not match the metrics recomputed from the pairs")).toBeVisible();
});

test("evidence explorer inspects hashes and rejects a tampered export", async ({ page, request }) => {
  const run = await (await request.post("/api/runs", { data: { scenario_id: "scope_manipulation" } })).json();
  await page.goto(`/evidence/?pair=${run.summary.pair_id}`);
  await expect(page.getByText("evidence verified")).toBeVisible();
  await page.getByRole("button", { name: /read_document.*hr\/payroll/ }).click();
  await expect(page.getByLabel(/event \d+ details/)).toContainText("outside granted scope");
  await shot(page, "evidence");

  const tampered = run.export;
  tampered.runs[1].outcome.attack_succeeded = true;
  await page.getByLabel("Evidence file").setInputFiles({
    name: "tampered.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(tampered)),
  });
  await expect(page.locator(".chip-failed", { hasText: "rejected" })).toBeVisible();
});

test("keyboard navigation reaches the main controls", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeFocused();
});
