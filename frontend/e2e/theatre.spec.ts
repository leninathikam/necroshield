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
  await expect(row("violation_patch")).toContainText("0/4");
  await expect(row("scoped_trace")).toContainText("4/4");
  await expect(row("scoped_trace")).toContainText("suggested");
  await expect(row("allow_all")).toContainText("rejected");
  await expect(row("global_scoped")).toContainText("7/11");
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
