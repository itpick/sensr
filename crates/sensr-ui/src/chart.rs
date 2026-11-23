//! The dashboard traffic charts: receive and transmit rates over time, with a rate axis,
//! a time axis and a crosshair that follows the pointer, a finger or the arrow keys.
//!
//! The lines live in a stretched SVG (`preserveAspectRatio="none"`); every piece of text
//! (axis labels, the tooltip) is HTML laid over it, so nothing is distorted.

use leptos::prelude::*;

/// One point of a traffic chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Seconds since the Unix epoch.
    pub ts: i64,
    /// Receive rate, bits/s.
    pub rx: u64,
    /// Transmit rate, bits/s.
    pub tx: u64,
}

/// A rate in bits per second, scaled.
pub fn bps(v: u64) -> String {
    let v = v as f64;
    if v >= 1e9 {
        format!("{:.2} Gbit/s", v / 1e9)
    } else if v >= 1e6 {
        format!("{:.1} Mbit/s", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.0} kbit/s", v / 1e3)
    } else {
        format!("{v:.0} bit/s")
    }
}

/// Rate axis ticks from 0 to the axis top: 3 or 4 equal steps of 1, 2, 2.5 or 5 times a
/// power of ten, the top at or above `max`. An idle chart still spans 1 kbit/s.
pub fn rate_ticks(max: u64) -> Vec<u64> {
    let max = max.max(1_000);
    let raw = max.div_ceil(4);
    let mut mag = 1u64;
    while mag * 10 <= raw {
        mag *= 10;
    }
    // raw >= 250, so mag >= 100 and 2.5 * mag is whole.
    let step = [mag, 2 * mag, 5 * mag / 2, 5 * mag, 10 * mag]
        .into_iter()
        .find(|s| *s >= raw)
        .unwrap_or(10 * mag);
    (0..=max.div_ceil(step)).map(|i| i * step).collect()
}

/// The unit an axis whose top tick is `top` is labelled in: (divisor, name).
pub fn rate_unit(top: u64) -> (u64, &'static str) {
    match top {
        t if t >= 1_000_000_000 => (1_000_000_000, "Gbit/s"),
        t if t >= 1_000_000 => (1_000_000, "Mbit/s"),
        t if t >= 1_000 => (1_000, "kbit/s"),
        _ => (1, "bit/s"),
    }
}

/// A tick value in the axis unit, without trailing zeros (`0`, `2.5`, `0.25`).
pub fn tick_label(v: u64, div: u64) -> String {
    let s = format!("{:.2}", v as f64 / div as f64);
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// The longest span a chart shows times for.
const DAY: i64 = 86_400;

/// The samples a chart draws, and whether their times are usable. Only the trailing run
/// whose timestamps never go backwards and lie within a day of the newest is kept: a clock
/// that jumped (a Pi without a battery-backed clock boots in 1970 until NTP sets it) ends
/// the run. Without usable times (one sample, or all the same, as when the backend sent
/// none) the run is spaced evenly by index and the chart shows no times.
pub fn prepare(s: &[Sample]) -> (Vec<Sample>, bool) {
    let Some(newest) = s.last().map(|p| p.ts) else {
        return (Vec::new(), false);
    };
    let mut start = s.len() - 1;
    while start > 0 && s[start - 1].ts <= s[start].ts && newest - s[start - 1].ts <= DAY {
        start -= 1;
    }
    let run = &s[start..];
    if run[0].ts < newest {
        return (run.to_vec(), true);
    }
    let by_index = run.iter().enumerate();
    (
        by_index
            .map(|(i, p)| Sample { ts: i as i64, ..*p })
            .collect(),
        false,
    )
}

/// Where the tooltip's left edge goes, in px from the plot's left edge, for a crosshair at
/// `px` in a plot `w` wide and a tooltip `tw` wide: beside the crosshair where it fits
/// (right, else left), otherwise centred on it but kept inside the plot, never over the
/// rate axis.
pub fn tip_left(px: f64, w: f64, tw: f64) -> f64 {
    const GAP: f64 = 10.0;
    if px + GAP + tw <= w {
        px + GAP
    } else if px - GAP - tw >= 0.0 {
        px - GAP - tw
    } else {
        (px - tw / 2.0).clamp(0.0, (w - tw).max(0.0))
    }
}

/// Time axis ticks: multiples (in local time, `offset` seconds east of UTC) of the
/// smallest round step that puts at most five ticks (four with seconds) in `t0..=t1`,
/// leaving out its first and last 6 % so a centred label never hangs off the chart. None
/// for a span that is empty or longer than a day.
pub fn time_ticks(t0: i64, t1: i64, offset: i64) -> Vec<i64> {
    const STEPS: [i64; 14] = [
        5, 10, 15, 30, 60, 120, 300, 600, 900, 1_800, 3_600, 7_200, 21_600, 86_400,
    ];
    if t1 <= t0 || t1 - t0 > DAY {
        return Vec::new();
    }
    let margin = (t1 - t0) * 6 / 100;
    let (lo, hi) = (t0 + margin, t1 - margin);
    let ticks = move |step: i64| {
        let first = (lo + offset).div_euclid(step) * step - offset;
        let first = if first < lo { first + step } else { first };
        (0..)
            .map(move |i| first + i * step)
            .take_while(move |t| *t <= hi)
    };
    let step = STEPS
        .into_iter()
        // HH:MM:SS labels are wider: at most four of them, five of HH:MM.
        .find(|s| ticks(*s).take(6).count() <= if *s < 60 { 4 } else { 5 })
        .unwrap_or(DAY);
    ticks(step).take(5).collect()
}

/// `HH:MM`, or `HH:MM:SS` when `seconds`, at `offset` seconds east of UTC.
pub fn clock(t: i64, offset: i64, seconds: bool) -> String {
    let s = (t + offset).rem_euclid(86_400);
    if seconds {
        format!("{:02}:{:02}:{:02}", s / 3_600, s / 60 % 60, s % 60)
    } else {
        format!("{:02}:{:02}", s / 3_600, s / 60 % 60)
    }
}

/// The browser's offset from UTC in seconds (0 on the server, which renders UTC until the
/// island hydrates).
fn local_offset() -> i64 {
    #[cfg(feature = "hydrate")]
    {
        let minutes = web_sys::js_sys::Date::new_0().get_timezone_offset();
        -(minutes as i64) * 60
    }
    #[cfg(not(feature = "hydrate"))]
    0
}

/// Index of the sample nearest to `t`.
fn nearest(s: &[Sample], t: i64) -> usize {
    let i = s.partition_point(|p| p.ts < t);
    match (i.checked_sub(1), s.get(i)) {
        (Some(a), Some(b)) if t - s[a].ts <= b.ts - t => a,
        (Some(a), None) => a,
        _ => i,
    }
}

/// Horizontal position of `t` in 0..=100.
fn x_pct(t: i64, t0: i64, t1: i64) -> f64 {
    if t1 > t0 {
        (t - t0) as f64 / (t1 - t0) as f64 * 100.0
    } else {
        100.0
    }
}

/// Vertical position of `v` on an axis topped at `top`, in 0..=100 from the top.
fn y_pct(v: u64, top: u64) -> f64 {
    100.0 - v as f64 / top.max(1) as f64 * 100.0
}

/// The parts of a chart that change with the data: the unit, the rate axis labels, the
/// SVG content (gridlines and both lines) and the time axis labels, as markup. Built as
/// strings rather than views to keep the island bundle small; there is no user text in it.
fn frame(s: &[Sample], timed: bool, off: i64) -> (&'static str, String, String, String) {
    let ticks = rate_ticks(s.iter().map(|p| p.rx.max(p.tx)).max().unwrap_or(0));
    let top = ticks.last().copied().unwrap_or(1);
    let (div, unit) = rate_unit(top);
    let (t0, t1) = (s.first().map_or(0, |p| p.ts), s.last().map_or(0, |p| p.ts));
    let mut y = String::new();
    let mut svg = String::new();
    for v in &ticks {
        let at = y_pct(*v, top);
        y += &format!(
            r#"<span style="top:{at:.2}%">{}</span>"#,
            tick_label(*v, div)
        );
        let class = if *v == 0 { "tc-base" } else { "tc-grid" };
        svg += &format!(r#"<line class="{class}" x1="0" x2="1000" y1="{at:.2}" y2="{at:.2}"/>"#);
    }
    for (class, tx) in [("spark-rx", false), ("spark-tx", true)] {
        svg += &format!(r#"<polyline class="{class}" fill="none" points=""#);
        for p in s {
            let v = if tx { p.tx } else { p.rx };
            svg += &format!("{:.1},{:.2} ", x_pct(p.ts, t0, t1) * 10.0, y_pct(v, top));
        }
        svg += r#""/>"#;
    }
    let times = if timed {
        time_ticks(t0, t1, off)
    } else {
        Vec::new()
    };
    // Offsets are whole minutes, so this is "some tick is not on the minute".
    let seconds = times.iter().any(|t| t % 60 != 0);
    let mut x = String::new();
    for t in times {
        x += &format!(
            r#"<span style="left:{:.2}%">{}</span>"#,
            x_pct(t, t0, t1),
            clock(t, off, seconds)
        );
    }
    (unit, y, svg, x)
}

/// The crosshair, the two dots and the tooltip at sample `i`, as markup, and the
/// crosshair's position in 0..=100. The browser then moves the tooltip beside it
/// ([`tip_left`]).
fn crosshair(s: &[Sample], i: usize, timed: bool, off: i64, labels: (&str, &str)) -> (String, f64) {
    let Some(p) = s.get(i) else {
        return (String::new(), 0.0);
    };
    let top = *rate_ticks(s.iter().map(|p| p.rx.max(p.tx)).max().unwrap_or(0))
        .last()
        .unwrap_or(&1);
    let (t0, t1) = (s[0].ts, s[s.len() - 1].ts);
    let x = x_pct(p.ts, t0, t1);
    let (ry, ty) = (y_pct(p.rx, top), y_pct(p.tx, top));
    let time = if timed {
        format!("<time>{}</time>", clock(p.ts, off, true))
    } else {
        String::new()
    };
    let html = format!(
        r#"<div class="tc-cross" style="left:{x:.2}%"></div><span class="tc-dot tc-dot-rx" style="left:{x:.2}%;top:{ry:.2}%"></span><span class="tc-dot tc-dot-tx" style="left:{x:.2}%;top:{ty:.2}%"></span><div class="tc-tip" style="left:{x:.2}%">{time}<span><span class="key key-rx"></span>{} {}</span><span><span class="key key-tx"></span>{} {}</span></div>"#,
        labels.0,
        bps(p.rx),
        labels.1,
        bps(p.tx)
    );
    (html, x)
}

/// What the slider says to assistive technology at sample `i` (or the latest): its
/// `aria-valuemax`, `aria-valuenow` and `aria-valuetext`.
fn aria(
    s: &[Sample],
    i: Option<usize>,
    timed: bool,
    off: i64,
    labels: (&str, &str),
) -> [String; 3] {
    let last = s.len().saturating_sub(1);
    let i = i.unwrap_or(last);
    let text = s.get(i).map_or_else(
        || "No samples yet".to_owned(),
        |p| {
            let rates = format!("{} {}, {} {}", labels.0, bps(p.rx), labels.1, bps(p.tx));
            if timed {
                format!("{}: {rates}", clock(p.ts, off, true))
            } else {
                rates
            }
        },
    );
    [last.to_string(), i.to_string(), text]
}

/// `s` escaped for an HTML attribute value.
fn attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The whole chart as markup: the unit, the rate axis, the plot (a slider for keyboard
/// and screen reader users) and the time axis.
fn chart_html(s: &[Sample], label: &str, labels: (&str, &str)) -> String {
    let (s, timed) = prepare(s);
    let (unit, y, svg, x) = frame(&s, timed, 0);
    let [max, now, text] = aria(&s, None, timed, 0, labels);
    format!(
        r#"<span class="tc-unit" aria-hidden="true">{unit}</span><div class="tc-y" aria-hidden="true">{y}</div><div class="tc-plot" tabindex="0" role="slider" aria-label="{}" aria-valuemin="0" aria-valuemax="{max}" aria-valuenow="{now}" aria-valuetext="{text}"><svg viewBox="0 0 1000 100" preserveAspectRatio="none" aria-hidden="true">{svg}</svg><div class="tc-hover" aria-hidden="true"></div></div><div class="tc-x" aria-hidden="true">{x}</div>"#,
        attr(label)
    )
}

/// A receive/transmit line chart with axes and a crosshair. The y axis is scaled to the
/// larger of the two series; `rx_label`/`tx_label` name them in the tooltip.
///
/// The server renders it as markup in UTC; in the browser two effects redraw it in local
/// time: one as the samples change, one as the crosshair moves. Markup and direct DOM writes
/// rather than a reactive view tree, because the island bundle has a size budget.
#[component]
pub fn TrafficChart(
    /// Samples, oldest first.
    samples: Memo<Vec<Sample>>,
    /// Accessible name of the chart.
    #[prop(into)]
    label: Signal<String>,
    /// Name of the receive series.
    #[prop(default = "In")]
    rx_label: &'static str,
    /// Name of the transmit series.
    #[prop(default = "Out")]
    tx_label: &'static str,
    /// Extra class on the chart (sets the plot height).
    #[prop(optional)]
    class: &'static str,
) -> impl IntoView {
    let labels = (rx_label, tx_label);
    // The hovered sample, by time, so it stays put while new samples arrive.
    let hover = RwSignal::new(None::<i64>);
    // Pointer moves within one sample change nothing: no redraw.
    let set_hover = move |v: Option<i64>| {
        if hover.get_untracked() != v {
            hover.set(v);
        }
    };
    let root = NodeRef::<leptos::html::Div>::new();
    // The hovered sample's index, snapped to the nearest one still shown.
    let current = move |s: &[Sample]| {
        let t = hover.get()?;
        (!s.is_empty()).then(|| nearest(s, t))
    };
    let find = move |sel: &str| {
        root.get()
            .and_then(|r| r.query_selector(sel).ok().flatten())
    };
    Effect::new(move |_| {
        let (unit, y, svg, x) = samples.with(|s| {
            let (s, timed) = prepare(s);
            frame(&s, timed, local_offset())
        });
        if let Some(e) = find(".tc-unit") {
            e.set_text_content(Some(unit));
        }
        for (sel, html) in [(".tc-y", y), (".tc-plot svg", svg), (".tc-x", x)] {
            if let Some(e) = find(sel) {
                e.set_inner_html(&html);
            }
        }
    });
    Effect::new(move |_| {
        let off = local_offset();
        let ((cross, x), aria) = samples.with(|s| {
            let (s, timed) = prepare(s);
            let i = current(&s);
            let cross = i.map_or_else(
                || (String::new(), 0.0),
                |i| crosshair(&s, i, timed, off, labels),
            );
            (cross, aria(&s, i, timed, off, labels))
        });
        if let Some(e) = find(".tc-hover") {
            e.set_inner_html(&cross);
        }
        if let (Some(plot), Some(tip)) = (find(".tc-plot"), find(".tc-tip")) {
            let w = f64::from(plot.client_width());
            // client_width leaves out the 1 px borders.
            let tw = f64::from(tip.client_width()) + 2.0;
            let left = tip_left(x / 100.0 * w, w, tw);
            let _ = tip.set_attribute("style", &format!("left:{left:.0}px"));
        }
        if let Some(e) = find(".tc-plot") {
            let _ = e.set_attribute("aria-label", &label.get());
            for (name, v) in ["aria-valuemax", "aria-valuenow", "aria-valuetext"]
                .into_iter()
                .zip(aria)
            {
                let _ = e.set_attribute(name, &v);
            }
        }
    });

    // Only the plot takes pointer events (the axes and everything inside the plot ignore
    // them), so a pointer over the plot has its offset from the plot's left edge, and one
    // over the axes hides the crosshair.
    let hover_at = move |ev: leptos::ev::MouseEvent| {
        let el = event_target::<leptos::web_sys::Element>(&ev);
        if !el.class_list().contains("tc-plot") {
            set_hover(None);
            return;
        }
        let x = f64::from(ev.offset_x()) / f64::from(el.client_width().max(1));
        set_hover(samples.with_untracked(|s| {
            let (s, _) = prepare(s);
            let (t0, t1) = (s.first()?.ts, s.last()?.ts);
            let t = t0 + (x.clamp(0.0, 1.0) * (t1 - t0) as f64) as i64;
            s.get(nearest(&s, t)).map(|p| p.ts)
        }));
    };
    let step = move |to: &dyn Fn(usize, usize) -> usize| {
        samples.with_untracked(|s| {
            let (s, _) = prepare(s);
            if s.is_empty() {
                return;
            }
            let i = untrack(|| current(&s)).unwrap_or(s.len() - 1);
            set_hover(Some(s[to(i, s.len() - 1)].ts));
        });
    };
    let on_key = move |ev: leptos::ev::KeyboardEvent| {
        // Leave modified keys (browser and screen reader shortcuts) alone.
        if ev.alt_key() || ev.ctrl_key() || ev.meta_key() || ev.shift_key() {
            return;
        }
        match ev.key().as_str() {
            "ArrowLeft" => step(&|i, _| i.saturating_sub(1)),
            "ArrowRight" => step(&|i, n| (i + 1).min(n)),
            "Home" => step(&|_, _| 0),
            "End" => step(&|_, n| n),
            "Escape" => set_hover(None),
            _ => return,
        }
        ev.prevent_default();
    };

    let html = samples.with_untracked(|s| chart_html(s, &label.get_untracked(), labels));
    view! {
        <div
            class=format!("tchart {class}")
            node_ref=root
            inner_html=html
            on:pointermove=move |ev| hover_at(ev.into())
            on:click=hover_at
            // A finger lifted or a scroll taking over (pointercancel is followed by
            // pointerleave) hides it too; a tap's click then shows that sample until the
            // next tap elsewhere moves focus away (focusout).
            on:pointerleave=move |_| set_hover(None)
            on:keydown=on_key
            on:focusout=move |_| set_hover(None)
        ></div>
    }
}
