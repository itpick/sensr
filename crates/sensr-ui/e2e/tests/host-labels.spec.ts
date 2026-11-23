import { expect, test, type Page } from "@playwright/test";
import { hydrated, login } from "./helpers";

// Smart host labels on the dashboard Hosts card: the guessed maker and kind under each MAC and
// the inline override editor. The mock backend is shared by every spec, so each test starts by
// dropping changes an earlier test left staged and ends with bench-pi back on its guessed label.
test.skip(!!process.env.SENSR_UI_BASE_URL, "relies on the mock's seeded hosts and their guessed labels");

const GUESS = "Raspberry Pi · Server?";

/** A label's text after its kind icon (one glyph, hidden from assistive tech). */
const shows = (text: string, open = false) =>
  new RegExp(`^[^A-Za-z]*${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}${open ? "" : "$"}`, "u");

const card = (page: Page) => page.locator("section.hosts-card");
const rows = (page: Page) => card(page).locator("tbody tr");
const banner = (page: Page) => page.getByRole("region", { name: "Pending changes" });
const row = (page: Page, host: string) =>
  rows(page).filter({ has: page.locator("td:first-child", { hasText: new RegExp(`^${host}$`) }) });
const label = (page: Page, host: string) => row(page, host).locator(".host-label");
const icon = (page: Page, host: string) => label(page, host).locator(".host-kind-icon");
const pencil = (page: Page, host: string) => row(page, host).getByRole("button", { name: `Edit label for ${host}` });
const typeSelect = (page: Page, host: string) => row(page, host).getByRole("combobox", { name: `Type for ${host}` });
const makerField = (page: Page, host: string) => row(page, host).getByRole("textbox", { name: `Maker for ${host}` });
const modeSelect = (page: Page, host: string) => row(page, host).getByRole("combobox", { name: `Mode for ${host}` });

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
  await discardStaged(page);
}

/** Puts bench-pi back on the guess if a test left an owner label behind. */
async function resetBenchPi(page: Page) {
  if ((await label(page, "bench-pi").textContent())?.includes(GUESS)) return;
  if ((await typeSelect(page, "bench-pi").count()) === 0) await pencil(page, "bench-pi").click();
  await row(page, "bench-pi").getByRole("button", { name: "Reset to auto" }).click();
  await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));
}

test.describe("host labels", () => {
  test.afterEach(async ({ page }) => {
    await resetBenchPi(page);
  });

  test("shows a smart label under the MAC", async ({ page }) => {
    await open(page);
    const mac = row(page, "bench-pi").locator("td").nth(1);
    await expect(mac).toContainText("b8:27:eb:7d:4e:25");
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));
    await expect(icon(page, "bench-pi")).toHaveText("🗄");
    await expect(icon(page, "bench-pi")).toHaveAttribute("aria-hidden", "true");
    // a low-confidence guess is italic and explains itself on hover
    await expect(label(page, "bench-pi")).toHaveClass(/\bhost-label-guess\b/);
    await expect(label(page, "bench-pi")).toHaveAttribute("title", /MAC maker: Raspberry Pi/);
  });

  test("override the type", async ({ page }) => {
    await open(page);
    await pencil(page, "bench-pi").click();
    await typeSelect(page, "bench-pi").selectOption({ label: "Camera" });
    await row(page, "bench-pi").getByRole("button", { name: "Save" }).click();
    await expect(label(page, "bench-pi")).toHaveText(shows("Raspberry Pi · Camera"));
    await expect(icon(page, "bench-pi")).toHaveText("📷");
    await expect(label(page, "bench-pi")).not.toHaveClass(/\bhost-label-guess\b/);
    await expect(label(page, "bench-pi")).toHaveAttribute("title", /Set by you/);
    await expect(typeSelect(page, "bench-pi")).toHaveCount(0);

    await pencil(page, "bench-pi").click();
    // the editor opens on the owner's choice
    await expect(typeSelect(page, "bench-pi")).toHaveValue("camera");
    await row(page, "bench-pi").getByRole("button", { name: "Reset to auto" }).click();
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));
  });

  test("override the maker", async ({ page }) => {
    await open(page);
    await pencil(page, "bench-pi").click();
    await makerField(page, "bench-pi").fill("Pi Foundation");
    await row(page, "bench-pi").getByRole("button", { name: "Save" }).click();
    // the kind stays the guess, but the owner's word makes the whole label sure: no "?"
    await expect(label(page, "bench-pi")).toHaveText(shows("Pi Foundation · Server"));
    await expect(icon(page, "bench-pi")).toHaveText("🗄");
    await expect(label(page, "bench-pi")).not.toHaveClass(/\bhost-label-guess\b/);
    // the guess's reasons follow the owner's
    await expect(label(page, "bench-pi")).toHaveAttribute("title", "Set by you\nMAC maker: Raspberry Pi");

    await pencil(page, "bench-pi").click();
    await expect(makerField(page, "bench-pi")).toHaveValue("Pi Foundation");
    await row(page, "bench-pi").getByRole("button", { name: "Reset to auto" }).click();
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));
  });

  test("keyboard: open, Escape, Enter", async ({ page }) => {
    await open(page);
    await expect(pencil(page, "bench-pi")).toHaveAttribute("aria-expanded", "false");
    await pencil(page, "bench-pi").focus();
    await page.keyboard.press("Enter");
    await expect(pencil(page, "bench-pi")).toHaveAttribute("aria-expanded", "true");
    await expect(typeSelect(page, "bench-pi")).toBeFocused();

    await page.keyboard.press("Escape");
    await expect(typeSelect(page, "bench-pi")).toHaveCount(0);
    await expect(pencil(page, "bench-pi")).toBeFocused();
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));

    await page.keyboard.press("Enter");
    await expect(typeSelect(page, "bench-pi")).toBeFocused();
    await makerField(page, "bench-pi").fill("Pi Foundation");
    await makerField(page, "bench-pi").press("Enter");
    await expect(label(page, "bench-pi")).toHaveText(shows("Pi Foundation · Server"));
    await expect(typeSelect(page, "bench-pi")).toHaveCount(0);
    await expect(pencil(page, "bench-pi")).toBeFocused();
  });

  test("the typed draft survives a Mode change on another row", async ({ page }) => {
    await open(page);
    await pencil(page, "bench-pi").click();
    await typeSelect(page, "bench-pi").selectOption("tv");
    await makerField(page, "bench-pi").fill("Acme");
    try {
      // the Mode change re-reads the hosts and re-renders every row
      await modeSelect(page, "device-03").selectOption("isolated");
      await expect(modeSelect(page, "device-03")).toHaveValue("isolated");
      await expect(typeSelect(page, "bench-pi")).toHaveValue("tv");
      await expect(makerField(page, "bench-pi")).toHaveValue("Acme");
    } finally {
      await modeSelect(page, "device-03").selectOption("normal");
      await expect(modeSelect(page, "device-03")).toHaveValue("normal");
    }
    await expect(typeSelect(page, "bench-pi")).toHaveValue("tv");
    await expect(makerField(page, "bench-pi")).toHaveValue("Acme");
    await page.keyboard.press("Escape");
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));
  });

  test("a randomised MAC reads as a private address", async ({ page }) => {
    await open(page);
    await expect(label(page, "device-02")).toHaveText(shows("Private MAC · Phone/laptop?"));
    await expect(icon(page, "device-02")).toHaveText("📱");
    await expect(label(page, "device-02")).toHaveClass(/\bhost-label-guess\b/);
    await expect(label(page, "device-02")).toHaveAttribute("title", /^Randomised address/);
  });

  test("staged path", async ({ page }) => {
    await open(page);
    // Stage an unrelated change so the label lands beside it instead of applying at once.
    await page.goto("/ui/system/general");
    await hydrated(page);
    await page.getByLabel("Hostname").fill("fw-labels");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved" })).toBeVisible();

    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    await pencil(page, "bench-pi").click();
    await typeSelect(page, "bench-pi").selectOption("tv");
    await row(page, "bench-pi").getByRole("button", { name: "Save" }).click();
    await expect(row(page, "bench-pi").locator(".host-label-staged")).toHaveText("Staged — Apply to take effect");
    // not in force yet: the guess still shows
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));

    // Discarding drops the unrelated change and the staged label together.
    await discardStaged(page);
    await expect(row(page, "bench-pi").locator(".host-label-staged")).toHaveCount(0);
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));
  });

  test("Make static and Forget stay side by side", async ({ page }) => {
    await open(page);
    const make = await row(page, "bench-pi").getByRole("button", { name: "Make static" }).boundingBox();
    const forget = await row(page, "bench-pi").getByRole("button", { name: "Forget" }).boundingBox();
    expect(make && forget).toBeTruthy();
    expect(Math.abs(make!.y - forget!.y)).toBeLessThan(2);
    expect(forget!.x).toBeGreaterThan(make!.x + make!.width - 1);
    // and ✎ sits on the label's line
    const text = await label(page, "bench-pi").boundingBox();
    const edit = await pencil(page, "bench-pi").boundingBox();
    expect(Math.abs(text!.y + text!.height / 2 - (edit!.y + edit!.height / 2))).toBeLessThan(6);
  });
});

test.describe("read-only user", () => {
  const port = Number(process.env.SENSR_UI_PORT ?? 3300) + 1;
  test.use({ baseURL: `http://127.0.0.1:${port}` });

  test("read-only user has no label editor", async ({ page }) => {
    await login(page);
    await page.goto("/ui/core/dashboard");
    await hydrated(page);
    await expect(label(page, "bench-pi")).toHaveText(shows(GUESS));
    await expect(card(page).getByRole("button", { name: /^Edit label for / })).toHaveCount(0);
  });
});
