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
