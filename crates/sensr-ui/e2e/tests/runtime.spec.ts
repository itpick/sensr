import { expect, test } from "@playwright/test";
import { hydrated, login } from "./helpers";

// Run-time status pages on the mock backend's synthetic gateway, feed and PD data.

test("gateways status page refreshes and the dashboard widget is filled", async ({ page }) => {
  await login(page);
  await expect(page.locator(".gw-list li")).toHaveCount(3);
  await page.goto("/ui/routing/status");
  await hydrated(page);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("System: Gateways: Status");
  const rows = page.locator(".gw-table tbody tr");
  await expect(rows).toHaveCount(3);
  await expect(rows.filter({ hasText: "BACKUP_GW" }).locator(".pill-warn")).toHaveText("Latency");
  await expect(rows.filter({ hasText: "WAN_DHCP6" })).toContainText("active");
  await expect(page.locator("[aria-labelledby=gw-groups]")).toContainText("WAN_FAILOVER");
  // The island polls every 5 s.
  await page.waitForResponse((r) => r.url().includes("/ui/fn/gateways_status"), { timeout: 8000 });
  await expect(rows).toHaveCount(3);
});

test("aliases: feed status columns and URL table refresh editing", async ({ page }) => {
  await login(page);
  await page.goto("/ui/firewall/alias");
  await hydrated(page);
  const row = page.locator(".grid tbody tr").filter({ hasText: "spamhaus_drop" });
  await expect(row).toContainText("UTC");
  await row.getByRole("button", { name: "Edit" }).click();
  const edit = page.getByRole("dialog", { name: "Edit alias" });
  await edit.getByLabel("Refresh frequency (days)").fill("1");
  await edit.getByLabel("Refresh frequency (hours)").fill("6");
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(edit).toBeHidden();
  await row.getByRole("button", { name: "Edit" }).click();
  await expect(edit.getByLabel("Refresh frequency (hours)")).toHaveValue("6");
  await edit.getByRole("button", { name: "Cancel" }).click();
  page.on("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Discard" }).click();
});

test("interfaces overview shows delegated prefixes", async ({ page }) => {
  await login(page);
  await page.goto("/ui/interfaces/overview");
  const pd = page.locator("[aria-labelledby=pd-head]");
  await expect(pd).toContainText("2001:db8:42::/56");
  await expect(pd.locator("tbody tr")).toHaveCount(2);
  await expect(pd.locator("tbody tr").nth(1)).toContainText("deprecated");
});
