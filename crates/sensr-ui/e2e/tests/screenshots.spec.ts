import { test } from "@playwright/test";
import { expectAccessible, hydrated, login, setTheme, shots } from "./helpers";

// Key pages of the routing slice, captured in both themes at desktop and phone width, each
// checked with axe in both themes (contrast differs per theme).
const pages: [string, string][] = [
  ["dashboard", "/"],
  ["interfaces-assignments", "/ui/interfaces/assignment"],
  ["interfaces-wan", "/ui/interfaces/if/wan"],
  ["firewall-aliases", "/ui/firewall/alias"],
  ["firewall-rules-lan", "/ui/firewall/filter/lan"],
  ["firewall-source-nat", "/ui/firewall/source_nat"],
  ["firewall-destination-nat", "/ui/firewall/d_nat"],
  ["services-dhcpv4-lan", "/ui/dhcpv4/lan"],
  ["services-unbound-general", "/ui/unbound/general"],
  ["services-unbound-overrides", "/ui/unbound/overrides"],
  ["services-unbound-advanced", "/ui/unbound/advanced"],
  ["services-unbound-acl", "/ui/unbound/acl"],
  ["services-unbound-blocklist", "/ui/unbound/dnsbl"],
  ["services-unbound-forward", "/ui/unbound/forward"],
  ["vpn-wireguard-instances", "/ui/wireguard/instances"],
  ["vpn-wireguard-peers", "/ui/wireguard/peers"],
  ["system-general", "/ui/system/general"],
  ["system-history", "/ui/core/backup/history"],
  ["services-ids-settings", "/ui/ids"],
  ["services-ids-rules", "/ui/ids/rules"],
  ["services-ids-userdefined", "/ui/ids/userdefined"],
  ["services-ids-alerts", "/ui/ids/alerts"],
  ["reporting-insight", "/ui/diagnostics/networkinsight"],
  ["reporting-insight-host", "/ui/diagnostics/networkinsight?range=7d&host=192.168.1.100"],
];

const viewports = { desktop: { width: 1366, height: 860 }, phone: { width: 390, height: 844 } };

for (const theme of ["light", "dark"] as const) {
  test(`login page (${theme})`, async ({ page }) => {
    await page.goto("/login");
    await setTheme(page, theme);
    for (const [vp, size] of Object.entries(viewports)) {
      await page.setViewportSize(size);
      await page.goto("/login");
      await page.screenshot({ path: `${shots}/${theme}/${vp}/login.png`, fullPage: true });
    }
    await expectAccessible(page);
  });

  for (const [name, url] of pages) {
    test(`${name} (${theme})`, async ({ page }) => {
      await login(page);
      await setTheme(page, theme);
      for (const [vp, size] of Object.entries(viewports)) {
        await page.setViewportSize(size);
        await page.goto(url);
        await hydrated(page);
        await page.screenshot({ path: `${shots}/${theme}/${vp}/${name}.png`, fullPage: true });
        if (vp === "desktop") await expectAccessible(page);
      }
    });
  }
}
