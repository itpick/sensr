import { expect, test } from "@playwright/test";
import { hydrated, login, shots } from "./helpers";

// Services › Unbound DNS against the mock backend (its blocklist statistics are simulated;
// on a real stack they come from files sensr-dns writes, so this spec is mock-only).

test.describe.configure({ mode: "serial" });

test("blocklist: grouped curated lists, validation, add, edit, delete, statistics", async ({ page }) => {
  await login(page);
  await page.goto("/ui/unbound/dnsbl");
  await hydrated(page);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Services: Unbound DNS: Blocklists");
  const rows = page.locator(".grid tbody tr");
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("HaGeZi PRO - Balanced Blocking");

  // Statistics from the last refresh and the resolver counters.
  const stats = page.getByRole("region", { name: "Statistics" });
  await expect(stats.locator("#dnsbl-names")).toHaveText("412,731");
  await expect(stats.locator("#unbound-queries")).toHaveText("1,284,377");
  await expect(stats).toContainText("Kids: 173,828 names");
  await expect(stats).toContainText("HTTP 503");
  await expect(stats).toContainText("does not count blocked queries per blocklist");

  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add blocklist policy" });
  await expect(dialog).toBeVisible();
  const lists = dialog.getByRole("group", { name: "Type of DNSBL" });
  await expect(lists.locator("legend")).toHaveText([
    "General Blocklists",
    "HaGeZi Multi - Clean the Internet",
    "OISD Blocklists",
    "HaGeZi Targeted Lists",
    "Minimal Hardware Requirements",
  ]);
  await expect(dialog.getByLabel("Refresh interval (seconds)")).toHaveValue("72000");
  await dialog.getByLabel("Description").fill("Guests");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(lists).toHaveAttribute("aria-invalid", "true");
  await expect(lists).toHaveAccessibleDescription(/Select a list, add a URL or name a domain to block/);

  await lists.getByLabel("HaGeZi PRO - Balanced Blocking", { exact: true }).check();
  await lists.getByLabel("OISD Ads Blocklist").check();
  await dialog.getByLabel("Allowlist Domains").fill("bad name");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog.getByLabel("Allowlist Domains")).toHaveAccessibleDescription(/not a name, \*\.name or \/regex\//);
  await page.screenshot({ path: `${shots}/interaction-dnsbl-validation.png` });
  await dialog.getByLabel("Allowlist Domains").fill("*.example.com\n/^cdn[0-9]+\\./");
  await dialog.getByLabel("Source Net(s)").fill("192.168.2.0/24");
  await dialog.getByLabel("Answer", { exact: true }).selectOption("nxdomain");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toBeHidden();
  await expect(rows).toHaveCount(3);
  const guests = rows.filter({ hasText: "Guests" });
  await expect(guests).toContainText("OISD Ads Blocklist");
  await expect(guests).toContainText("192.168.2.0/24");

  // Edit keeps the selection.
  await guests.getByRole("button", { name: "Edit" }).click();
  const edit = page.getByRole("dialog", { name: "Edit blocklist policy" });
  await expect(edit.getByLabel("OISD Ads Blocklist")).toBeChecked();
  await expect(edit.getByLabel("Answer", { exact: true })).toHaveValue("nxdomain");
  await edit.getByLabel("OISD Ads Blocklist").uncheck();
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(edit).toBeHidden();
  await expect(guests).not.toContainText("OISD Ads Blocklist");

  page.once("dialog", (d) => d.accept());
  await guests.getByRole("button", { name: "Delete" }).click();
  await expect(rows).toHaveCount(2);
});

test("host overrides: PTR on by default, stored TTL shown", async ({ page }) => {
  await login(page);
  await page.goto("/ui/unbound/overrides");
  await hydrated(page);
  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add host override" });
  await expect(dialog.getByLabel("Add PTR record")).toBeChecked();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  const lab = page.locator(".grid tbody tr").filter({ hasText: "Lab wildcard" });
  await lab.getByRole("button", { name: "Edit" }).click();
  const edit = page.getByRole("dialog", { name: "Edit host override" });
  await expect(edit.getByLabel("Add PTR record")).not.toBeChecked();
  await expect(edit.getByLabel("TTL (seconds)")).toHaveValue("300");
});

test("query forwarding: domain overrides, DNS over TLS servers kept apart", async ({ page }) => {
  await login(page);
  await page.goto("/ui/unbound/forward");
  await hydrated(page);
  const rows = page.locator(".grid tbody tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("corp.example");
  await expect(page.getByLabel("Use System Nameservers")).not.toBeChecked();

  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add forwarding server" });
  await dialog.getByLabel("Domain").fill("lab.example");
  await dialog.getByLabel("Server IP").fill("nope");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog.getByLabel("Server IP")).toHaveAccessibleDescription(/valid IPv4 or IPv6/);
  await dialog.getByLabel("Server IP").fill("192.168.1.53");
  await dialog.getByLabel("Server Port").fill("5353");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toBeHidden();
  await expect(rows).toHaveCount(2);
  await expect(rows.filter({ hasText: "lab.example" })).toContainText("5353");
});

test("access lists: default action and a list needing networks", async ({ page }) => {
  await login(page);
  await page.goto("/ui/unbound/acl");
  await hydrated(page);
  await expect(page.getByLabel("Default Action")).toHaveValue("allow");
  const rows = page.locator(".grid tbody tr");
  await expect(rows).toHaveCount(2);
  await page.getByRole("button", { name: "Add" }).click();
  const dialog = page.getByRole("dialog", { name: "Add access list" });
  await dialog.getByLabel("Access List Name").fill("admins");
  await dialog.getByLabel("Action", { exact: true }).selectOption("allow_snoop");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog.getByLabel("Networks")).toHaveAccessibleDescription(/required/);
  await dialog.getByLabel("Networks").fill("192.168.1.10/32");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toBeHidden();
  await expect(rows).toHaveCount(3);
  await expect(rows.filter({ hasText: "admins" })).toContainText("allow_snoop");

  await page.getByLabel("Default Action").selectOption("refuse");
  await page.locator("form.settings-form").getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Saved" })).toBeVisible();
});

test("advanced: one form per section, cache size validation", async ({ page }) => {
  await login(page);
  await page.goto("/ui/unbound/advanced");
  await hydrated(page);
  for (const h of ["General settings", "Serve expired settings", "Logging settings", "Cache settings"]) {
    await expect(page.getByRole("heading", { name: h })).toBeVisible();
  }
  await expect(page.getByLabel("Harden Below NXDOMAIN")).toBeChecked();
  await expect(page.getByLabel("Log Level Verbosity")).toHaveValue("2");
  const cache = page.locator("section.card").filter({ has: page.getByRole("heading", { name: "Cache settings" }) });
  await expect(cache.getByLabel("Message Cache Size")).toHaveValue("8m");
  await cache.getByLabel("Message Cache Size").fill("lots");
  await cache.getByRole("button", { name: "Save" }).click();
  await expect(cache.getByLabel("Message Cache Size")).toHaveAccessibleDescription(/size such as 4m/);
  await cache.getByLabel("Message Cache Size").fill("16m");
  await cache.getByRole("button", { name: "Save" }).click();
  await expect(cache.getByRole("status")).toHaveText(/Saved/);
  await page.reload();
  await expect(page.getByLabel("Message Cache Size")).toHaveValue("16m");
  await expect(page.getByLabel("Prefetch Support")).toBeChecked();
});

test("general: DNS64 prefix must be IPv6", async ({ page }) => {
  await login(page);
  await page.goto("/ui/unbound/general");
  await hydrated(page);
  await expect(page.getByLabel("Enable Statistics")).toBeChecked();
  await page.getByLabel("DNS64 Prefix").fill("10.0.0.0/8");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByLabel("DNS64 Prefix")).toHaveAccessibleDescription(/IPv6 prefix/);
  await page.getByLabel("DNS64 Prefix").fill("64:ff9b::/96");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Saved" })).toBeVisible();
});
