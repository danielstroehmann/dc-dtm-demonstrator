// A minimal DOM stand-in for running app/static/app.js under node (no browser, no npm packages): elements with
// attributes, dataset, hidden and a selector matcher (compound tag/#id/.class/[attr] parts, descendant combinator),
// enough for the side panel's click handling. Usage: node app_js_dom.js <path/to/app.js>
// Prints a JSON report of the panel's state after each step.
"use strict";
const fs = require("fs");
const vm = require("vm");

const camel = (name) => name.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
const kebab = (key) => key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);

class Element {
  constructor(tag, attrs = {}) {
    this.tagName = tag;
    this.attrs = { ...attrs };
    this.children = [];
    this.parentElement = null;
    this.hidden = "hidden" in this.attrs;
    this.style = {};
    const el = this;
    this.dataset = new Proxy({}, {
      get: (_, key) => el.attrs[`data-${kebab(String(key))}`],
      set: (_, key, value) => { el.attrs[`data-${kebab(String(key))}`] = String(value); return true; },
      deleteProperty: (_, key) => { delete el.attrs[`data-${kebab(String(key))}`]; return true; },
      has: (_, key) => `data-${kebab(String(key))}` in el.attrs,
    });
    this.classList = {
      contains: (c) => el.classes().includes(c),
      add: (c) => { if (!el.classes().includes(c)) el.attrs.class = [...el.classes(), c].join(" "); },
      remove: (c) => { el.attrs.class = el.classes().filter((x) => x !== c).join(" "); },
      toggle: (c, on) => { (on ?? !el.classes().includes(c)) ? el.classList.add(c) : el.classList.remove(c); },
    };
  }
  classes() { return (this.attrs.class || "").split(/\s+/).filter(Boolean); }
  set className(value) { this.attrs.class = value; }
  get className() { return this.attrs.class || ""; }
  get id() { return this.attrs.id || ""; }
  getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  append(...nodes) { for (const n of nodes) { n.parentElement = this; this.children.push(n); } return this; }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  *descendants() { for (const c of this.children) { yield c; yield* c.descendants(); } }
  matchesCompound(part) {
    const re = /([#.]?)([\w-]+)|\[([\w-]+)\]/g;
    let m;
    while ((m = re.exec(part))) {
      if (m[3] !== undefined) { if (!(m[3] in this.attrs)) return false; }
      else if (m[1] === "#") { if (this.id !== m[2]) return false; }
      else if (m[1] === ".") { if (!this.classes().includes(m[2])) return false; }
      else if (this.tagName !== m[2]) return false;
    }
    return true;
  }
  matches(selector) {
    return selector.split(",").some((sel) => {
      const parts = sel.trim().split(/\s+/);
      if (parts.some((p) => p.includes(":"))) return false;  // pseudo-classes are not modelled
      if (!this.matchesCompound(parts.pop())) return false;
      let node = this.parentElement;
      while (parts.length && node) {
        if (node.matchesCompound(parts[parts.length - 1])) parts.pop();
        node = node.parentElement;
      }
      return parts.length === 0;
    });
  }
  closest(selector) {
    for (let node = this; node; node = node.parentElement) if (node.matches(selector)) return node;
    return null;
  }
  querySelectorAll(selector) { return [...this.descendants()].filter((n) => n.matches(selector)); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

const listeners = {};
const body = new Element("body");
const document = {
  body,
  documentElement: { clientWidth: 1280 },
  createElement: (tag) => new Element(tag),
  addEventListener: (type, fn) => { (listeners[type] ||= []).push(fn); },
  getElementById: (id) => body.querySelector(`#${id}`),
  querySelectorAll: (s) => body.querySelectorAll(s),
  querySelector: (s) => body.querySelector(s),
};
const ajax = [];
const context = {
  document,
  window: { addEventListener() {}, scrollX: 0, scrollY: 0 },
  htmx: { ajax: (method, url, opts) => ajax.push(url) },
  navigator: {},
  localStorage: { getItem: () => null, setItem() {} },
  setInterval: () => 0,  // the countdown ticker must not keep node alive
  setTimeout: () => 0,
  console,
};

// The page: a device tile (outside the panel) with its certificates, and the side panel as in _device_card.html
const tile = new Element("article", { class: "tile" });
const certsBox = new Element("div", { class: "tile-certs", "data-certs": "/runs/r1/devices/d1/certificates", tabindex: "0" });
tile.append(certsBox);
const panel = new Element("aside", { id: "side-panel", class: "side-panel", hidden: "" });
const close = new Element("button", { class: "panel-close outline btn-sm", "data-panel-close": "" });
panel.append(close, new Element("div", { class: "panel-tile" }), new Element("div", { class: "panel-certs" }));
body.append(tile, panel);

vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), context, { filename: "app.js" });

const click = (target) => { for (const fn of listeners.click || []) fn({ target }); };
const state = () => ({ hidden: panel.hidden, certs: panel.dataset.certs ?? null, ajax: [...ajax] });
const report = {};
click(certsBox);
report.afterOpen = state();
click(close);
report.afterClose = state();
process.stdout.write(JSON.stringify(report));
