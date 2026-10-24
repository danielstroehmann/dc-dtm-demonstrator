"""A browser stand-in for the guided New-run form: parses the rendered HTML (stdlib only), applies
the same data-when rules as app/static/app.js `showQuestions` / `applyGuide` and returns what the
browser would submit.
It lets component tests check that every path through the guide posts a form the server accepts –
without a JS engine. Keep it in step with app.js: groups split by "|" (any), conditions by
whitespace (all), values read from checked/number/select inputs outside hidden data-when elements,
hidden elements disable their inputs, repeat until stable; only then a checked-but-disabled radio
falls back to the first enabled one of its group, the questions settle again, and that repeats
until nothing moves (at most 5 times)."""

from html.parser import HTMLParser

VOID = {"input", "br", "meta", "link", "img", "hr", "source", "col", "wbr"}


class Node:
    def __init__(self, tag: str, attrs: dict, parent: "Node | None"):
        self.tag, self.attrs, self.parent, self.children = tag, attrs, parent, []
        self.hidden = False
        self.disabled = "disabled" in attrs
        self.checked = "checked" in attrs
        self.value = attrs.get("value") or ""
        self.text = ""

    def walk(self):
        for child in self.children:
            yield child
            yield from child.walk()

    def ancestors(self):
        node = self.parent
        while node:
            yield node
            node = node.parent


class _Builder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", {}, None)
        self.current = self.root

    def handle_starttag(self, tag, attrs):
        node = Node(tag, {k: (v if v is not None else "") for k, v in attrs}, self.current)
        self.current.children.append(node)
        if tag not in VOID:
            self.current = node

    def handle_startendtag(self, tag, attrs):
        self.current.children.append(Node(tag, {k: (v if v is not None else "") for k, v in attrs}, self.current))

    def handle_endtag(self, tag):
        node = self.current
        while node is not self.root and node.tag != tag:
            node = node.parent
        if node is not self.root:
            self.current = node.parent

    def handle_data(self, data):
        self.current.text += data


class GuideForm:
    def __init__(self, html: str):
        builder = _Builder()
        builder.feed(html)
        self.form = next(n for n in builder.root.walk() if n.tag == "form" and "data-guide" in n.attrs)
        self.nodes = list(self.form.walk())
        self.apply()

    # --- the browser side ------------------------------------------------------------------
    def inputs(self):
        return [n for n in self.nodes if n.tag in ("input", "select")]

    def _values(self) -> dict:
        values = {}
        for node in self.inputs():
            if any(a.hidden and "data-when" in a.attrs for a in [node, *node.ancestors()]):
                continue
            kind = node.attrs.get("type", "text")
            if node.tag == "select":
                options = [o for o in node.walk() if o.tag == "option"]
                chosen = next((o for o in options if "selected" in o.attrs), options[0] if options else None)
                values[node.attrs["name"]] = chosen.attrs.get("value", "") if chosen else ""
            elif (kind in ("radio", "checkbox") and node.checked) or kind == "number":
                values[node.attrs["name"]] = node.value
        return values

    def show_questions(self) -> None:
        """showQuestions: visibility until stable (at most 5 passes)."""
        for _ in range(5):
            values = self._values()
            before = [n.hidden for n in self.nodes if "data-when" in n.attrs]
            for node in self.nodes:
                if "data-when" not in node.attrs:
                    continue
                parent = next((a for a in node.ancestors() if "data-when" in a.attrs), None)
                show = not (parent and parent.hidden) and any(
                    all(values.get(c.split("=")[0]) == c.split("=", 1)[1] for c in group.split())
                    for group in node.attrs["data-when"].split("|"))
                node.hidden = not show
                for child in node.walk():
                    if child.tag in ("input", "select"):
                        child.disabled = not show
            if [n.hidden for n in self.nodes if "data-when" in n.attrs] == before:
                return

    def apply(self) -> None:
        """applyGuide: settle the questions, then move a checked-but-disabled radio to the first enabled
        one of its group and settle again – until nothing moves (at most 5 rounds)."""
        self.show_questions()
        for _ in range(5):  # a fallback can reveal or hide further questions – repeat until nothing moves
            moved = False
            for group in (n for n in self.nodes if n.attrs.get("role") == "radiogroup"):
                radios = [n for n in group.walk() if n.tag == "input"]
                checked = next((r for r in radios if r.checked), None)
                first = next((r for r in radios if not r.disabled), None)
                if checked and checked.disabled and first:
                    for radio in radios:
                        radio.checked = radio is first
                    moved = True
            if not moved:
                return
            self.show_questions()

    # --- the user side ---------------------------------------------------------------------
    def options(self, name: str) -> list[str]:
        """Radio values the user can see and click."""
        return [n.value for n in self.inputs() if n.attrs.get("name") == name and n.attrs.get("type") == "radio"
                and not n.disabled and not self.is_hidden(n)]

    def is_hidden(self, node: Node) -> bool:
        return any(a.hidden for a in [node, *node.ancestors()] if "data-when" in a.attrs)

    def visible(self, name: str) -> bool:
        return any(not self.is_hidden(n) and not n.disabled for n in self.inputs() if n.attrs.get("name") == name)

    def choose(self, name: str, value: str) -> None:
        radios = [n for n in self.inputs() if n.attrs.get("name") == name and n.attrs.get("type") == "radio"]
        target = next(r for r in radios if r.value == value)
        assert not target.disabled and not self.is_hidden(target), f"{name}={value} is not offered"
        for radio in radios:
            radio.checked = radio is target
        self.apply()

    def set(self, name: str, value: str) -> None:
        node = next(n for n in self.inputs() if n.attrs.get("name") == name)
        assert not node.disabled and not self.is_hidden(node), f"{name} is not offered"
        if node.attrs.get("type") == "checkbox":
            node.checked = bool(value)
        else:
            node.value = value
        self.apply()

    def visible_text(self, needle: str) -> bool:
        """True if an element containing the text is not hidden by data-when."""
        return any(needle in n.text and not self.is_hidden(n) for n in self.nodes)

    def submission(self) -> dict:
        """FormData: enabled inputs only; radios/checkboxes when checked."""
        data = {}
        for node in self.inputs():
            if node.disabled or "name" not in node.attrs:
                continue
            kind = node.attrs.get("type", "text")
            if node.tag == "select":
                options = [o for o in node.walk() if o.tag == "option"]
                chosen = next((o for o in options if "selected" in o.attrs), options[0] if options else None)
                if chosen is not None:
                    data[node.attrs["name"]] = chosen.attrs.get("value", "")
            elif kind in ("radio", "checkbox"):
                if node.checked:
                    data[node.attrs["name"]] = node.value or "on"
            else:
                data[node.attrs["name"]] = node.value
        return data
