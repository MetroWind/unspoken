const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../static/photos.js"), "utf8");

test("Warning must be opened before photo bytes are requested", function()
{
    const warning = {tagName: "DETAILS", open: false, parentElement: null};
    const image = {
        dataset: {photoSrc: "https://remote.test/private.jpg"},
        parentElement: {tagName: "A", parentElement: warning},
        removeAttribute() { delete this.dataset.photoSrc; }
    };
    const handlers = {};
    const document = {
        addEventListener(name, handler) { handlers[name] = handler; },
        querySelectorAll(selector)
        {
            return selector === "img[data-photo-src]" && image.dataset.photoSrc
                ? [image] : [];
        }
    };
    vm.runInNewContext(source, {document});
    assert.equal(image.src, undefined);
    handlers.toggle();
    assert.equal(image.src, undefined);
    warning.open = true;
    handlers.toggle();
    assert.equal(image.src, "https://remote.test/private.jpg");
});

function galleryHarness(options = {})
{
    const state = {
        mutations: [], gallery_list: [],
        reduced_motion: false
    };

    function makeGallery(count = 3, start = 0)
    {
        const pips = Array.from({length: count}, function(_, index)
        {
            return {
                dataset: {photoIndex: String(index)}, disabled: true,
                attributes: {}, classes: new Set(), handlers: {},
                setAttribute(name, value) { this.attributes[name] = value; },
                removeAttribute(name) { delete this.attributes[name]; },
                addEventListener(name, handler) { this.handlers[name] = handler; },
                removeEventListener(name, handler)
                {
                    if(this.handlers[name] === handler) delete this.handlers[name];
                },
                click()
                {
                    if(!this.disabled && this.handlers.click)
                        this.handlers.click({currentTarget: this});
                }
            };
        });
        pips.forEach(function(pip)
        {
            pip.classList = {toggle(name, active)
            {
                if(active) pip.classes.add(name);
                else pip.classes.delete(name);
            }};
        });
        const pip_row = {querySelectorAll() { return pips; }};
        const gallery = {
            scrollLeft: start, clientWidth: 300, clientLeft: 2,
            scrollWidth: count * 300 + Math.max(0, count - 1) * 12,
            handlers: {}, scroll_calls: [], isConnected: true,
            parentElement: {querySelector() { return count > 1 ? pip_row : null; }},
            getBoundingClientRect() { return {left: 40, width: 304}; },
            addEventListener(name, handler) { this.handlers[name] = handler; },
            removeEventListener(name, handler)
            {
                if(this.handlers[name] === handler) delete this.handlers[name];
            },
            scrollTo(position)
            {
                this.scroll_calls.push(position);
                this.scrollLeft = position.left;
                if(this.handlers.scroll) this.handlers.scroll();
            }
        };
        gallery.children = Array.from({length: count}, function(_, index)
        {
            return {
                tagName: index === 1 ? "DETAILS" : "IMG",
                getBoundingClientRect()
                {
                    return {left: 42 + index * 312 - gallery.scrollLeft,
                        width: 300};
                }
            };
        });
        gallery.pips = pips;
        state.gallery_list.push(gallery);
        return gallery;
    }

    class MutationObserver
    {
        constructor(callback) { state.mutations.push(callback); }
        observe() {}
    }
    const document = {
        body: {}, addEventListener() {},
        querySelectorAll(selector)
        {
            if(selector === ".photo-post .gallery")
                return state.gallery_list.filter(function(gallery)
                {
                    return gallery.isConnected;
                });
            return [];
        }
    };
    const gallery = makeGallery(options.count ?? 3, options.start ?? 0);
    vm.runInNewContext(source, {
        document, MutationObserver,
        matchMedia() { return {matches: state.reduced_motion}; }
    });
    return {state, gallery, makeGallery};
}

test("Manual horizontal scrolling updates pips, including sensitive slides", function()
{
    const {gallery} = galleryHarness();
    assert.equal(gallery.pips[0].attributes["aria-current"], "true");
    assert.equal(gallery.pips[0].disabled, false);
    gallery.scrollLeft = 312;
    gallery.handlers.scroll();
    assert.equal(gallery.children[1].tagName, "DETAILS");
    assert.equal(gallery.pips[0].attributes["aria-current"], undefined);
    assert.equal(gallery.pips[1].attributes["aria-current"], "true");
    assert.equal(gallery.pips[1].classes.has("active"), true);
    gallery.scrollLeft = 624;
    gallery.handlers.scroll();
    assert.equal(gallery.pips[1].classes.has("active"), false);
    assert.equal(gallery.pips[2].attributes["aria-current"], "true");
});

test("Pip clicks use slide positions and respect reduced motion", function()
{
    const {state, gallery} = galleryHarness();
    gallery.pips[1].click();
    assert.equal(gallery.scroll_calls[0].left, 312);
    assert.equal(gallery.scroll_calls[0].behavior, "smooth");
    assert.equal(gallery.scroll_calls[0].top, undefined);
    state.reduced_motion = true;
    gallery.pips[2].click();
    assert.equal(gallery.scroll_calls[1].left, 624);
    assert.equal(gallery.scroll_calls[1].behavior, "auto");
});

test("Gallery keyboard navigation clamps at both ends", function()
{
    const {gallery} = galleryHarness();
    let prevented = 0;
    function key(value, target = gallery)
    {
        gallery.handlers.keydown({key: value, target,
            preventDefault() { ++prevented; }});
    }
    key("ArrowLeft");
    assert.equal(gallery.scroll_calls.at(-1).left, 0);
    key("ArrowRight");
    assert.equal(gallery.scroll_calls.at(-1).left, 312);
    gallery.scrollLeft = 624;
    gallery.handlers.scroll();
    key("ArrowRight");
    assert.equal(gallery.scroll_calls.at(-1).left, 624);
    const calls = gallery.scroll_calls.length;
    key("ArrowRight", gallery.children[1]);
    key("Enter");
    assert.equal(gallery.scroll_calls.length, calls);
    assert.equal(prevented, 3);
});

test("Pips reflect the initial scroll position", function()
{
    const {gallery} = galleryHarness({start: 312});
    assert.equal(gallery.pips[1].attributes["aria-current"], "true");
    gallery.pips[2].click();
    assert.equal(gallery.pips[2].attributes["aria-current"], "true");
});

test("Inline replacements remove old listeners and initialize once", function()
{
    const {state, gallery, makeGallery} = galleryHarness();
    const scroll_handler = gallery.handlers.scroll;
    state.mutations[0]();
    assert.equal(gallery.handlers.scroll, scroll_handler);
    gallery.isConnected = false;
    const replacement = makeGallery();
    state.mutations[0]();
    assert.equal(gallery.handlers.scroll, undefined);
    assert.equal(gallery.handlers.keydown, undefined);
    assert.equal(gallery.pips[0].handlers.click, undefined);
    replacement.pips[1].click();
    assert.equal(replacement.pips[1].attributes["aria-current"], "true");
});

test("Single-photo galleries need no pip controls", function()
{
    const {gallery} = galleryHarness({count: 1});
    assert.equal(gallery.handlers.scroll, undefined);
    assert.equal(gallery.handlers.keydown, undefined);
});

test("Attachment queue appends batches and preserves descriptions", function()
{
    class Element
    {
        constructor(tag)
        {
            this.tagName = tag.toUpperCase();
            this.children = [];
            this.handlers = {};
            this.value = "";
        }
        setAttribute() {}
        removeAttribute() {}
        addEventListener(name, handler) { this.handlers[name] = handler; }
        appendChild(child) { this.children.push(child); }
        replaceChildren() { this.children = []; }
        querySelector(selector)
        {
            if(selector === "input")
            {
                for(const child of this.children)
                {
                    if(child.tagName === "INPUT") return child;
                    if(child.querySelector)
                    {
                        const found = child.querySelector(selector);
                        if(found) return found;
                    }
                }
            }
            return null;
        }
        querySelectorAll() { return this.children; }
        focus() {}
    }
    const input = new Element("input");
    input.files = [];
    input.required = true;
    const picker = new Element("input");
    input.cloneNode = () => picker;
    input.replaceWith = () => {};
    const mode = new Element("input");
    mode.value = "photo";
    const status = new Element("p");
    const controls = new Element("div");
    const form = {addEventListener() {}, querySelector(selector)
    {
        return {'[name="post_kind"]': mode, 'input[name="attachments"]': input,
            ".photo-mode-status": status}[selector];
    }};
    const container = {
        appendChild() {},
        closest() { return form; },
        querySelector(selector)
        {
            return selector === ".upload-descriptions" ? controls : input;
        }
    };
    class DataTransfer
    {
        constructor()
        {
            this.files = [];
            this.items = {add: (file) => this.files.push(file)};
        }
    }
    const document = {
        addEventListener() {},
        querySelectorAll(selector)
        {
            return selector === ".photo-uploads" ? [container] : [];
        },
        createElement(tag) { return new Element(tag); },
        createTextNode(value) { return {textContent: value}; }
    };
    const revoked = [];
    const URL = {
        createObjectURL(file) { return "blob:" + file.name; },
        revokeObjectURL(url) { revoked.push(url); }
    };
    vm.runInNewContext(source, {document, DataTransfer, URL});
    const first = {name: "first.png", type: "image/png"};
    const second = {name: "notes.txt", type: "text/plain"};
    picker.files = [first];
    picker.handlers.change();
    assert.equal(picker.value, "");
    assert.equal(picker.required, false);
    assert.equal(controls.children[0].children[1].src, "blob:first.png");
    const description = controls.children[0].querySelector("input");
    description.value = "First description";
    description.handlers.input();
    picker.files = [second];
    picker.handlers.change();
    assert.deepEqual(input.files, [first, second]);
    controls.children[0].children.at(-1).handlers.click();
    assert.equal(input.files[0], second);
    assert.equal(controls.children[1].querySelector("input").value,
        "First description");
    assert.equal(controls.children[1].querySelector("input").name,
        "attachment_description_1");
    assert.match(status.textContent, /Some selected files/);
    assert.equal(input.files.length, 2);
    assert.equal(mode.value, "photo");
    controls.children[1].children.find(child =>
        child.textContent === "Remove").handlers.click();
    assert.deepEqual(revoked, ["blob:first.png"]);
    assert.deepEqual(input.files, [second]);
    controls.children[0].children.find(child =>
        child.textContent === "Remove").handlers.click();
    assert.equal(picker.required, true);
});
