# UI design v2 – first impression, style guide, screens

> Status: implemented 2026-10-24. The author's direction after the first mockups: calm and attractive,
> **no extra text** – screens show what to do, not why.

## Why

The first minutes decide how the demonstrator is perceived – like the road from the airport into a
capital. Today the start is the weakest part: a bare login card with a full-width button, a home
page that is a heading plus one orange button, the use-case choice one level deeper, and Pico's
default full-width submit buttons on every form.

## Style guide (binding for all screens)

| Rule | Detail |
|---|---|
| Brand | docs.digicert.com look: Roboto, blue `#1976d2`, header gradient `#004ba0 → #003a7d`, greys; no DigiCert logos – generic shield icon |
| **Buttons** | **Never full width** – sized to their label on every screen size (overrides Pico's `button[type=submit] { width: 100% }`) |
| Primary action | One per page. Orange (`.cta`) only for the action that starts something (Start run, first connection); otherwise blue |
| Action placement | Form actions in an **action bar** at the end of the form, right-aligned (phones: left), *Cancel* as a plain link left of the primary button |
| Surfaces | Light grey page (`#f7f9fb`), white cards with soft shadow and rounded corners; blue top line only on the card in focus |
| Status | **Pills** with a coloured dot: green ok, red failed, blue running (pulsing, off with reduced motion), grey idle |
| Choices | Two to three options = **segmented control**, not a radio list; on/off = switch |
| Forms | Grouped **sections** (title on the left, fields on the right; stacked on phones); help text only where a format must be known |
| Tables | Unchanged: one line per row, custom tooltip when clipped |
| Text | As little as possible: no taglines, no explanatory side panels, no italics. Tiles show title and tags only |
| Icons | Inline SVG, stroke style, `currentColor`, `aria-hidden` – no icon font, no images (Lighthouse 100) |
| Motion | Only hover lift on tiles and the running pill; all off under `prefers-reduced-motion` |

## Quality bar (author, 2026-10-25 – binding, reference: the UC-5 run overview)

Desktop browsers only. A screen is done when it passes these – checked on the real page, not in the code.

| Rule | Detail |
|---|---|
| **Same page head everywhere** | Every page starts with the breadcrumb ("Use-Case Central" first, current page last; home: "Use-Case Central" only) and the h1 – via `_page_head.html`, so headings sit at the same height on every page |
| **One grid per row** | Elements side by side share one grid: same number of columns, equal widths, equal box heights, shared top and bottom edges (form controls: `--control-h`) |
| **Phases** | Factory = blue box (`.box.accent`) with factory icon chip; field = orange box (`.box.accent.field`) with its own chip. Same look in the overview and in the reproducible steps; two phases with results stand side by side (`.phase-pair`) |
| **Metric groups** | At most four metrics per group, in a fixed grid (`.metrics-4`); short labels ("Per minute"), the unit in the value |
| **Outcomes** | Checks: pill *passed* / *failed* plus DTM's own message (`dtm_message`) – never raw JSON or API text; the full answer only as tooltip. Raw API lines belong in the timeline's API entries and the reproducible steps only |
| **Less text** | No meta lines that repeat what the page already says (counts, protocol, names – the header line has the context); headings are short noun phrases ("Passcode enforced") |
| **Labels are terms** | Expert tool: field labels are nouns ("Key generation", "Devices", "Authentication", "Run via"), never questions – the options say the rest ("DTM (server-side)" / "Factory"); no explanations that repeat a badge or the block a step is in |
| **Done means seen** | Screenshot review on `https://localhost:8443` with real data at ~1440, 1280 and 1024 px; a new view also gets a separate UX reviewer. Tests and code review do not replace this |

## Screens

| # | Screen | Concept |
|---|---|---|
| 1 | **Log in** | Split screen: blue brand panel (name, one headline) and a compact form. Phones: brand band on top |
| 2 | **Welcome** (no DTM connection) | Three-step stepper and the connection form – the first action happens on this page |
| 3 | **Home** | "Start a demo": use-case tiles (icon, ID, title, tags, *Start*), connection picker when there are several; recent runs with status pills; empty state |
| 4 | **New run** | Breadcrumb, use case as title; form in sections (Run, Issuance, Certificate) with segmented controls; action bar *Cancel* · *Start run* |
| 5 | **Run** | Header with run ID, status pill and one context line; stepper Run → Result → Clean up; then the existing cards |
| 6 | **Settings** | Connections as a list (name, default badge, host · account, actions right); form with action bar |

App shell: header with brand, *Runs*, *Settings*, the default connection as a chip (from the local
store – no DTM call) and a log-out icon button.

`/runs/new` stays as the use-case page (same tiles as the home page) so existing links keep working.
