import { expect, test, type Page } from "@playwright/test";
import { hydrated, login } from "./helpers";

// Per-host modes on the dashboard Hosts card. The mock backend is shared by every spec, so each
// test starts by dropping changes an earlier test left staged and ends with the host back on Normal.
test.skip(!!process.env.SENSR_UI_BASE_URL, "relies on the mock's seeded hosts and client MAC");

const card = (page: Page) => page.locator("section.hosts-card");
const rows = (page: Page) => card(page).locator("tbody tr");
const banner = (page: Page) => page.getByRole("region", { name: "Pending changes" });
const modeSelect = (page: Page, host: string) => rows(page).filter({ hasText: host }).getByRole("combobox", { name: `Mode for ${host}` });

async function discardStaged(page: Page) {
  const discard = banner(page).getByRole("button", { name: "Discard" });
  if (await discard.isVisible()) {
    page.once("dialog", (d) => void d.accept());
    await discard.click();
    await expect(banner(page)).not.toContainText("The configuration has been changed");
  }
}

async function open(page: Page) {
  await login(page);
  await page.goto("/ui/core/dashboard");
  await hydrated(page);
  await expect(card(page).getByRole("heading", { name: /^Hosts \(\d+\)$/ })).toBeVisible();
  await expect(rows(page)).toHaveCount(20);
  await discardStaged(page);
}

test.describe("host modes", () => {
  test("set a host to Isolated", async ({ page }) => {
    await open(page);
    const pi = rows(page).filter({ hasText: "bench-pi" });
    await modeSelect(page, "bench-pi").selectOption("isolated");
    await expect(pi.locator(".pill-warn")).toHaveText("Isolated");
    await expect(modeSelect(page, "bench-pi")).toHaveValue("isolated");

    await modeSelect(page, "bench-pi").selectOption("normal");
    await expect(pi.locator(".pill-warn")).toHaveCount(0);
    await expect(modeSelect(page, "bench-pi")).toHaveValue("normal");
  });

  test("quarantine shows the footer help", async ({ page }) => {
    await open(page);
    // device-05 is seeded Quarantine, so the help is already showing; lock another host too.
    await modeSelect(page, "bench-pi").selectOption("quarantine");
    await expect(modeSelect(page, "bench-pi")).toHaveValue("quarantine");
    await expect(card(page)).toContainText("Same-network blocking works by redirecting");

    await modeSelect(page, "bench-pi").selectOption("normal");
    await expect(modeSelect(page, "bench-pi")).toHaveValue("normal");
  });

  test("self-quarantine is refused", async ({ page }) => {
    await open(page);
    await modeSelect(page, "device-01").selectOption("quarantine");
    await expect(card(page).getByRole("alert")).toHaveText(
      "That's the device you're using — quarantine it from another device.",
    );
    await expect(modeSelect(page, "device-01")).toHaveValue("normal");
  });

  test("staged path", async ({ page }) => {
    await open(page);
    // Stage an unrelated change so the mode change lands beside it instead of applying at once.
    await page.goto("/ui/system/general");
    await hydrated(page);
    await page.getByLabel("Hostname").fill("fw-modes");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved" })).toBeVisible();

    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    await expect(rows(page)).toHaveCount(20);
    await modeSelect(page, "bench-pi").selectOption("isolated");
    await expect(rows(page).filter({ hasText: "bench-pi" }).locator(".host-mode-staged")).toHaveText(
      "Staged — Apply to take effect",
    );
    await expect(modeSelect(page, "bench-pi")).toHaveValue("isolated");

    // Discarding drops the unrelated change and the staged mode together.
    await discardStaged(page);
    await expect(modeSelect(page, "bench-pi")).toHaveValue("normal");
  });
});

test.describe("read-only user", () => {
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 1;
  test.use({ baseURL: `http://127.0.0.1:${port}` });

  test("read-only user has no Mode select", async ({ page }) => {
    await open(page);
    await expect(card(page).getByRole("combobox", { name: /^Mode for / })).toHaveCount(0);
  });
});
