const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(__dirname + "/../static/sticker_picker.js", "utf8");

class Element
{
    constructor(tag)
    {
        this.tag = tag;
        this.children = [];
        this.dataset = {};
        this.attributes = {};
        this.handlers = {};
        this.nodeType = 1;
        this.isConnected = true;
        this.hidden = false;
    }
    append(...children)
    {
        children.forEach(child => { child.parent = this; });
        this.children.push(...children);
    }
    replaceChildren() { this.children = []; }
    setAttribute(key, value) { this.attributes[key] = value; }
    getAttribute(key) { return this.attributes[key] ?? null; }
    removeAttribute(key) { delete this.attributes[key]; }
    addEventListener(key, handler) { this.handlers[key] = handler; }
    focus() { this.focused = true; }
    showModal() { this.open = true; }
    close() { this.open = false; this.handlers.close(); }
    get firstElementChild() { return this.children[0]; }
    closest(selector)
    {
        if(selector === "[data-sticker-index]")
            return this.dataset.stickerIndex !== undefined ? this : null;
        if(selector === "[data-pack-index]")
            return this.dataset.packIndex !== undefined ? this : null;
        if(selector === "form") return this.form;
        return this;
    }
    querySelectorAll() { return this.children; }
}

function setup()
{
    const handlers = {};
    const body = new Element("body");
    const document = {
        body, currentScript: {dataset: {catalog: "/stickers/catalog"}},
        createElement(tag) { return new Element(tag); },
        addEventListener(key, handler) { handlers[key] = handler; },
        querySelectorAll() { return []; }
    };
    let requests = 0;
    async function fetch(url)
    {
        ++requests;
        assert.equal(url, "/stickers/catalog");
        return {ok: true, async json() { return [
            {name: "cats <&>", stickers: [
                {key: "one", url: "/one", name: "one <&>"},
                {key: "two", url: "/two", name: "two"}]},
            {name: "birds", stickers: [{key: "bird", url: "/bird", name: "bird"}]}
        ]; }};
    }
    class MutationObserver { observe() {} }
    vm.runInNewContext(source, {document, fetch, WeakMap, MutationObserver,
        window: {fetch, HTMLDialogElement: true}});
    const dialog = body.children[0];
    function form()
    {
        const image = new Element("img");
        image.setAttribute("src", "/saved");
        image.alt = "saved";
        const selection = {hidden: false};
        const node = {
            elements: {sticker: {value: ""}, sticker_action: {value: "keep"}},
            querySelector(selector)
            {
                return selector === ".sticker-preview" ? image : selection;
            }
        };
        const trigger = new Element("button");
        trigger.form = node;
        trigger.classList = {contains() { return false; }};
        const remove = new Element("button");
        remove.form = node;
        remove.classList = {contains() { return true; }};
        return {node, trigger, remove, image, selection};
    }
    return {handlers, dialog, tabs: dialog.children[0], grid: dialog.children[1],
        form, get requests() { return requests; }};
}

test("SelectionReplacementIsolationAndCatalogReuse", async function()
{
    const state = setup();
    const first = state.form();
    const second = state.form();
    await state.handlers.click({target: first.trigger});
    assert.equal(state.dialog.open, true);
    assert.equal(state.tabs.children[0].textContent, "cats <&>");
    state.grid.handlers.click({target: state.grid.children[0]});
    assert.equal(first.node.elements.sticker_action.value, "set");
    assert.equal(first.node.elements.sticker.value, "one");
    assert.equal(first.image.alt, "one <&>");
    assert.equal(second.node.elements.sticker_action.value, "keep");
    assert.equal(state.dialog.open, false);
    assert.equal(first.trigger.focused, true);
    await state.handlers.click({target: first.trigger});
    state.grid.handlers.click({target: state.grid.children[1]});
    assert.equal(first.node.elements.sticker.value, "two");
    await state.handlers.click({target: second.trigger});
    assert.equal(state.requests, 1);
    state.tabs.handlers.keydown({target: state.tabs.children[0],
        key: "ArrowRight", preventDefault() {}});
    assert.equal(state.tabs.children[1].attributes["aria-selected"], "true");
    assert.equal(state.tabs.children[1].focused, true);
    state.grid.handlers.click({target: state.grid.children[0]});
    assert.equal(second.node.elements.sticker.value, "bird");
    assert.equal(first.node.elements.sticker.value, "two");
});

test("RemovalAndCancellationRestoreSavedPreview", async function()
{
    const state = setup();
    const form = state.form();
    await state.handlers.click({target: form.remove});
    assert.equal(form.node.elements.sticker_action.value, "clear");
    assert.equal(form.node.elements.sticker.value, "");
    assert.equal(form.selection.hidden, true);
    state.handlers.reset({target: form.node});
    assert.equal(form.selection.hidden, false);
    assert.equal(form.image.src, "/saved");
    assert.equal(form.image.alt, "saved");
    await state.handlers.click({target: form.trigger});
    // Native dialog Escape generates close and returns focus.
    state.dialog.close();
    assert.equal(form.trigger.attributes["aria-expanded"], "false");
    assert.equal(form.trigger.focused, true);
});
