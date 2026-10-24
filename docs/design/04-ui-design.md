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
