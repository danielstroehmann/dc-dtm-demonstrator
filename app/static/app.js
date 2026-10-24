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
      el.querySelectorAll("input, select").forEach((input) => { input.disabled = !show; });
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
