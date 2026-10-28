// Small client helpers (no inline script – CSP script-src 'self').

// Copy buttons for the API call snippets.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const source = document.getElementById(button.dataset.copy);
  if (!source || !navigator.clipboard) return;
  navigator.clipboard.writeText(source.textContent).then(() => {
    const label = button.textContent;
    button.textContent = "Copied ✓";
    setTimeout(() => { button.textContent = label; }, 1500);
  });
});

// Confirmations in the app's own dialog instead of the browser's window.confirm().
document.addEventListener("htmx:confirm", (event) => {
  const question = event.detail.question;
  if (!question) return;
  event.preventDefault();
  const dialog = document.getElementById("confirm-dialog");
  dialog.querySelector("[data-confirm-text]").textContent = question;
  dialog.querySelector("[data-confirm-ok]").textContent = event.detail.elt.dataset.confirmLabel || "Confirm";
  dialog.returnValue = "";
  dialog.addEventListener("close", () => {
    if (dialog.returnValue === "ok") event.detail.issueRequest(true);
  }, { once: true });
  dialog.showModal();
});

// Tooltips in the app's style instead of the browser's title bubbles: shown for elements with
// data-tip, and for clipped text (ellipsis) in metric labels and compact tables.
const TRUNCATING = ".metrics small, table.compact td, table.compact th, table.data-table td, table.data-table th";
const tip = document.createElement("div");
tip.className = "tooltip";
tip.setAttribute("role", "tooltip");
document.body.append(tip);

function tipText(el) {
  if (el.dataset.tip) return el.dataset.tip;
  return el.matches(TRUNCATING) && el.scrollWidth > el.clientWidth ? el.textContent.trim() : "";
}

function showTip(el) {
  const text = tipText(el);
  if (!text) return;
  tip.textContent = text;
  tip.classList.add("show");
  const box = el.getBoundingClientRect();
  const left = Math.min(Math.max(8, box.left + box.width / 2 - tip.offsetWidth / 2),
                        document.documentElement.clientWidth - tip.offsetWidth - 8);
  const above = box.top - tip.offsetHeight - 8;
  tip.classList.toggle("below", above < 0);
  tip.style.left = `${left + window.scrollX}px`;
  tip.style.top = `${(above < 0 ? box.bottom + 8 : above) + window.scrollY}px`;
}

function hideTip() { tip.classList.remove("show"); }

for (const [on, off] of [["mouseover", "mouseout"], ["focusin", "focusout"]]) {
  document.addEventListener(on, (event) => {
    const el = event.target.closest(`[data-tip], ${TRUNCATING}`);
    if (el) showTip(el);
  });
  document.addEventListener(off, hideTip);
}
document.addEventListener("scroll", hideTip, { passive: true });

// Guided form (New run → Evergreen Device IDs): a question is shown only while its data-when
// applies ("name=value name=value | …" – all of a group, any group). Hidden questions are disabled,
// so they are not submitted; a hidden option never stays selected. The server checks again.
function showQuestions(form) {
  // Answers can hide questions that hide others – repeat until nothing changes. Values are read
  // from the inputs themselves (FormData skips disabled ones, i.e. answers hidden a moment ago).
  for (let pass = 0; pass < 5; pass++) {
    const values = {};
    form.querySelectorAll("input:checked, input[type=number], select").forEach((input) => {
      if (!input.closest("[data-when][hidden]")) values[input.name] = input.value;
    });
    const before = [...form.querySelectorAll("[data-when]")].map((el) => el.hidden).join();
    form.querySelectorAll("[data-when]").forEach((el) => {
      const parent = el.parentElement.closest("[data-when]");
      const show = !(parent && parent.hidden) && el.dataset.when.split("|").some((group) =>
        group.trim().split(/\s+/).every((cond) => {
          const [name, value] = cond.split("=");
          return values[name] === value;
        }));
      el.hidden = !show;
      // the element itself may be the input (the inline count) – disable it too, so it is not submitted
      [el, ...el.querySelectorAll("input, select")].filter((n) => n.matches("input, select"))
        .forEach((input) => { input.disabled = !show; });
    });
    if ([...form.querySelectorAll("[data-when]")].map((el) => el.hidden).join() === before) return;
  }
}

function applyGuide(form) {
  showQuestions(form);
  // Only once the questions are settled: a hidden option must not stay selected.
  for (let pass = 0; pass < 5; pass++) {
    let moved = false;
    form.querySelectorAll('[role="radiogroup"]').forEach((group) => {
      const inputs = [...group.querySelectorAll("input")];
      const checked = inputs.find((i) => i.checked);
      const first = inputs.find((i) => !i.disabled);
      if (checked && checked.disabled && first) {
        first.checked = true;
        moved = true;
      }
    });
    if (!moved) return;
    showQuestions(form);
  }
}
document.querySelectorAll("form[data-guide]").forEach((form) => {
  form.addEventListener("change", () => applyGuide(form));
  applyGuide(form);
});

// Countdowns (UC-8 tiles: the TrustEdge agent's next connect) – the server renders the target time, the browser ticks.
// Also right after htmx swaps a polled tile in, so the fresh tile never shows its placeholder.
function tickCountdowns() {
  for (const el of document.querySelectorAll("[data-until]")) {
    const left = Math.round((Date.parse(el.dataset.until) - Date.now()) / 1000);
    el.textContent = left > 0 ? `next connect in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : "connecting any moment";
  }
}
setInterval(tickCountdowns, 1000);
document.addEventListener("htmx:afterSwap", tickCountdowns);
document.addEventListener("DOMContentLoaded", tickCountdowns);

// Minion wall (from 11 devices): counter chips filter, the search highlights by name / CN / serial, a click on a cell
// opens that device's tile in the side panel (same actions as a tile). Cells stay plain <use> elements – classes only.
// A tile's certificates (wall panel or large tile) open their detail view in the same panel.
function wallSearch(input) {
  const wall = input.closest(".card").querySelector(".wall");
  const query = input.value.trim().toLowerCase();
  wall.classList.toggle("searching", query !== "");
  for (const cell of wall.querySelectorAll("use[data-n]")) {
    cell.classList.toggle("hit", query !== "" && `${cell.dataset.tip} ${cell.dataset.s}`.toLowerCase().includes(query));
  }
  return wall.querySelector("use.hit");
}

// tile: URL of the tile to show above the detail, null to show none, undefined to keep the one shown
function openPanel(certs, tile) {
  const panel = document.getElementById("side-panel");
  const tileBox = panel.querySelector(".panel-tile");
  const certsBox = panel.querySelector(".panel-certs");
  panel.hidden = false;
  if (tile !== undefined) tileBox.replaceChildren();  // the old tile must not keep polling
  if (tile) htmx.ajax("GET", tile, { target: tileBox });  // htmx swaps the inner content by default
  certsBox.replaceChildren();  // a device without certificates answers 404 – nothing of the previous one stays
  htmx.ajax("GET", certs, { target: certsBox });
}

function openDevice(cell) {
  const wall = cell.closest(".wall");
  wall.querySelector("use.selected")?.classList.remove("selected");
  cell.classList.add("selected");
  const device = `/runs/${wall.dataset.run}/devices/${encodeURIComponent(cell.dataset.n)}`;
  openPanel(`${device}/certificates`, `${device}/tile?i=${cell.dataset.i}`);
}

function openCertificates(box) {
  const inPanel = box.closest("#side-panel") !== null;
  if (!inPanel) document.querySelector(".wall use.selected")?.classList.remove("selected");
  openPanel(box.dataset.certs, inPanel ? undefined : null);
}

function closePanel() {
  const panel = document.getElementById("side-panel");
  if (!panel || panel.hidden) return;
  panel.hidden = true;
  panel.querySelector(".panel-tile").replaceChildren();  // its tile must not keep polling
  panel.querySelector(".panel-certs").replaceChildren();
  document.querySelector(".wall use.selected")?.classList.remove("selected");
}

document.addEventListener("click", (event) => {
  const cell = event.target.closest(".wall use[data-n]");
  if (cell) return openDevice(cell);
  const certs = event.target.closest("[data-certs]");
  if (certs) return openCertificates(certs);
  if (event.target.closest("[data-panel-close]")) return closePanel();
  const chip = event.target.closest(".wall-chip");
  if (!chip) return;
  const wall = chip.closest(".card").querySelector(".wall");
  const on = chip.getAttribute("aria-pressed") !== "true";
  chip.parentElement.querySelectorAll(".wall-chip").forEach((c) => c.setAttribute("aria-pressed", "false"));
  chip.setAttribute("aria-pressed", String(on));
  if (on) wall.dataset.filter = chip.dataset.filter; else delete wall.dataset.filter;
});
document.addEventListener("input", (event) => {
  if (event.target.matches(".wall-search")) wallSearch(event.target);
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closePanel();
  if (event.key === "Enter" && event.target.matches("[data-certs]")) openCertificates(event.target);
  if (event.key === "Enter" && event.target.matches(".wall-search")) {
    event.preventDefault();
    const hit = wallSearch(event.target);
    if (hit) openDevice(hit);
  }
});

// While a batch issues, the polled wall pops the cells whose state changed.
let wallBefore = null;
document.addEventListener("htmx:beforeSwap", (event) => {
  if (event.detail.target.id === "devices") {
    wallBefore = [...event.detail.target.querySelectorAll(".wall use")].map((cell) => cell.getAttribute("class"));
  }
});
document.addEventListener("htmx:afterSettle", () => {
  if (!wallBefore) return;
  document.querySelectorAll("#devices .wall use").forEach((cell, i) => {
    if (wallBefore[i] !== undefined && wallBefore[i] !== cell.getAttribute("class")) cell.classList.add("pop");
  });
  wallBefore = null;
});

// Timeline Debug toggle: every API call and heartbeat, full height – remembered in this browser only
function applyDebug(on) {
  for (const card of document.querySelectorAll(".timeline-card")) {
    card.classList.toggle("debug", on);
    card.querySelector("[data-debug-toggle]")?.setAttribute("aria-pressed", String(on));
  }
}
function storedDebug() {
  try { return localStorage.getItem("timelineDebug") === "1"; } catch { return false; }
}
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-debug-toggle]");
  if (!button) return;
  const on = !button.closest(".timeline-card").classList.contains("debug");
  try { localStorage.setItem("timelineDebug", on ? "1" : "0"); } catch { /* private window: this page only */ }
  applyDebug(on);
});
document.addEventListener("DOMContentLoaded", () => applyDebug(storedDebug()));
document.addEventListener("htmx:afterSwap", () => applyDebug(storedDebug()));
