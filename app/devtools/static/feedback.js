// Feedback overlay (dev builds only): floating button → pick an element → comment → save.
// Stable selectors come from @medv/finder, the screenshot from html2canvas (both vendored, see vendor/).
import { finder } from "./vendor/finder-4.0.2.js";

const MARK = "data-feedback-ui";  // everything of the overlay – never picked, never in the screenshot

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.setAttribute(MARK, "");
  node.append(...children);
  return node;
}

const button = el("button", { type: "button", className: "fb-button", textContent: "Feedback",
  title: "Comment on an element of this page" });
const box = el("div", { className: "fb-highlight" });
const hint = el("div", { className: "fb-hint", textContent: "Click the element you want to comment on · Esc cancels" });
const target = el("p", { className: "fb-target" });
const comment = el("textarea", { name: "comment", rows: 4, maxLength: 4000, required: true,
  placeholder: "What should change?" });
const status = el("small", { className: "fb-status" });
const cancel = el("button", { type: "button", className: "secondary outline", textContent: "Cancel" });
const save = el("button", { type: "submit", textContent: "Save" });
const form = el("form", {}, target, comment, status, el("div", { className: "fb-actions" }, cancel, save));
const dialog = el("dialog", { className: "fb-dialog" }, el("article", {}, el("h3", { textContent: "Feedback" }), form));
const toast = el("div", { className: "fb-toast", role: "status" });
document.body.append(button, box, hint, dialog, toast);

let picked = null;

function ours(node) { return node instanceof Element && node.closest(`[${MARK}]`); }

function frame(node) {
  const r = node.getBoundingClientRect();
  Object.assign(box.style, { top: `${r.top}px`, left: `${r.left}px`, width: `${r.width}px`, height: `${r.height}px` });
  box.classList.add("fb-on");
}

function component(node) {
  // Template/component names marked in the markup, outermost first, plus the nearest id.
  const names = [];
  for (let n = node.closest("[data-component]"); n; n = n.parentElement?.closest("[data-component]")) {
    names.unshift(n.dataset.component);
  }
  const id = node.closest("[id]")?.id;
  if (id) names.push(`#${id}`);
  return names.join(" › ");
}

function visibleText(node) {
  const text = node.innerText || node.value || node.getAttribute("aria-label") || node.dataset.tip || node.title || "";
  return text.replace(/\s+/g, " ").trim().slice(0, 2000);
}

function selectorOf(node) {
  try { return finder(node, { timeoutMs: 500 }); } catch { return node.tagName.toLowerCase(); }
}

function onMove(event) { if (!ours(event.target)) frame(event.target); }

function onClick(event) {
  if (ours(event.target)) return;
  // Capture phase on the document: the page's own handlers (links, htmx, forms) never see this click.
  event.preventDefault();
  event.stopImmediatePropagation();
  stopPicking();
  picked = event.target;
  frame(picked);
  const text = visibleText(picked);
  target.textContent = `${component(picked) || picked.tagName.toLowerCase()}${text ? ` – “${text.slice(0, 120)}”` : ""}`;
  comment.value = "";
  status.textContent = "";
  dialog.showModal();
}

function onKey(event) { if (event.key === "Escape") { stopPicking(); box.classList.remove("fb-on"); } }

function startPicking() {
  document.documentElement.classList.add("fb-picking");
  document.addEventListener("mousemove", onMove, true);
  document.addEventListener("click", onClick, true);
  document.addEventListener("keydown", onKey, true);
}

function stopPicking() {
  document.documentElement.classList.remove("fb-picking");
  document.removeEventListener("mousemove", onMove, true);
  document.removeEventListener("click", onClick, true);
  document.removeEventListener("keydown", onKey, true);
}

async function screenshot(node) {
  // The visible viewport at scale 1, the picked element framed in DigiCert orange.
  const canvas = await window.html2canvas(document.body, {
    // clientWidth/-Height: the viewport without scrollbars
    x: window.scrollX, y: window.scrollY,
    width: document.documentElement.clientWidth, height: document.documentElement.clientHeight,
    scale: 1, logging: false, ignoreElements: (n) => n.hasAttribute?.(MARK),
  });
  const r = node.getBoundingClientRect();
  const ctx = canvas.getContext("2d");
  ctx.strokeStyle = "#f57c00";
  ctx.lineWidth = 3;
  ctx.strokeRect(r.left, r.top, r.width, r.height);
  return new Promise((resolve, reject) =>
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("no screenshot"))), "image/png"));
}

function close() {
  dialog.close();
  box.classList.remove("fb-on");
  picked = null;
}

function notify(message) {
  toast.textContent = message;
  toast.classList.add("fb-on");
  setTimeout(() => toast.classList.remove("fb-on"), 3000);
}

button.addEventListener("click", startPicking);
cancel.addEventListener("click", close);
dialog.addEventListener("close", () => { box.classList.remove("fb-on"); });
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!picked || !comment.value.trim()) return;
  save.disabled = true;
  status.textContent = "Saving …";
  const node = picked;
  const data = new FormData();
  data.append("comment", comment.value.trim());
  data.append("selector", selectorOf(node));
  data.append("component", component(node));
  data.append("text", visibleText(node));
  data.append("url", location.pathname + location.search);
  data.append("viewport", `${window.innerWidth}x${window.innerHeight}@${Math.round(window.devicePixelRatio * 100) / 100}`);
  try {
    dialog.close();  // not in the screenshot
    data.append("screenshot", await screenshot(node), "screenshot.png");
    const response = await fetch("/feedback", { method: "POST", body: data, credentials: "same-origin" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    close();
    notify("Feedback saved");
  } catch (error) {
    status.textContent = `Not saved: ${error.message}`;
    dialog.showModal();
  } finally {
    save.disabled = false;
  }
});
