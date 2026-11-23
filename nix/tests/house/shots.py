# Screenshots of the sensr dashboard from a LAN client (house.nix with
# screenshots = true), headless Chromium through Playwright.
#
#   shots.py BASE_URL OUT_DIR USER PASSWORD EDIT_HOST
#
# Each shot is tried on its own; the exit code is the number that failed.
import os
import re
import sys
import traceback

from playwright.sync_api import sync_playwright

BASE, OUT, USER, PASSWORD, EDIT = sys.argv[1:6]
os.makedirs(OUT, exist_ok=True)
failed = []


def shot(name, fn):
    try:
        fn(os.path.join(OUT, name + ".png"))
        print(f"SHOT ok   {name}", flush=True)
    except Exception:  # noqa: BLE001 - every shot on its own
        failed.append(name)
        print(f"SHOT FAIL {name}", flush=True)
        traceback.print_exc()


def hydrated(page):
    page.wait_for_function(
        "() => Number(document.documentElement.dataset.islands ?? 0)"
        " >= document.querySelectorAll('leptos-island').length",
        timeout=60000,
    )


def dashboard(browser, theme, width, height, phone=False):
    ctx = browser.new_context(
        viewport={"width": width, "height": height},
        ignore_https_errors=True,
        device_scale_factor=2 if phone else 1,
        is_mobile=phone,
        has_touch=phone,
    )
    ctx.add_cookies([{"name": "sensr_theme", "value": theme, "url": BASE}])
    page = ctx.new_page()
    page.set_default_timeout(30000)
    page.goto(BASE + "/login")
    page.get_by_label("Username").fill(USER)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Login").click()
    page.locator('nav[aria-label="Main menu"]').wait_for(state="attached")
    page.goto(BASE + "/")
    hydrated(page)
    hosts = page.locator("section.hosts-card")
    hosts.wait_for()
    more = hosts.get_by_role("button", name=re.compile(r"^Show all"))
    if more.count():
        more.first.click()
    # a refresh or two (every 3 s), so the charts have the latest samples
    page.wait_for_timeout(7000)
    return ctx, page


def centre(loc):
    loc.evaluate("e => e.scrollIntoView({block: 'center'})")


def hover(page, plot, fx):
    centre(plot)
    box = plot.bounding_box()
    page.mouse.move(box["x"] + box["width"] * fx, box["y"] + box["height"] / 2)


with sync_playwright() as p:
    browser = p.chromium.launch(channel="chromium", headless=True, args=["--disable-gpu", "--no-sandbox"])

    ctx, page = dashboard(browser, "light", 1440, 900)
    hosts = page.locator("section.hosts-card")
    shot("dashboard-1440-light", lambda f: page.screenshot(path=f, full_page=True))
    shot("hosts-card-light", lambda f: (centre(hosts), hosts.screenshot(path=f)))

    def graph_hover(f):
        card = page.locator("section", has=page.get_by_role("heading", name="Traffic graph", exact=True))
        hover(page, card.locator(".tc-plot").first, 0.6)
        card.locator(".tc-tip").wait_for()
        card.screenshot(path=f)

    shot("traffic-graph-hover", graph_hover)

    def iface_hover(f):
        card = page.locator("section", has=page.get_by_role("heading", name="Traffic", exact=True))
        hover(page, card.locator(".tc-plot").first, 0.6)
        card.locator(".tc-tip").first.wait_for()
        card.screenshot(path=f)

    shot("traffic-interfaces-hover", iface_hover)
    page.mouse.move(0, 0)

    def label_editor(f):
        pencil = hosts.get_by_role("button", name=re.compile(rf"^Edit label for {re.escape(EDIT)}", re.I)).first
        centre(pencil)
        pencil.click()
        hosts.get_by_role("combobox", name=re.compile(r"^Type for ")).first.wait_for()
        hosts.screenshot(path=f)
        page.keyboard.press("Escape")

    shot("label-editor", label_editor)
    ctx.close()

    ctx, page = dashboard(browser, "dark", 1440, 900)
    hosts = page.locator("section.hosts-card")
    shot("dashboard-1440-dark", lambda f: page.screenshot(path=f, full_page=True))
    shot("hosts-card-dark", lambda f: (centre(hosts), hosts.screenshot(path=f)))
    ctx.close()

    ctx, page = dashboard(browser, "light", 390, 844, phone=True)
    shot("dashboard-390-light", lambda f: page.screenshot(path=f, full_page=True))
    ctx.close()
    browser.close()

print(f"SHOTS {len(failed)} failed: {failed}", flush=True)
sys.exit(len(failed))
