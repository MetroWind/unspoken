// Run with: node --test tests/post_editor_test.js
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(
    __dirname, "../static/post_editor.js"), "utf8");

function setup(mode)
{
    const handlers = {};
    const status = {textContent: ""};
    const textarea = {disabled: false, value: "My draft", focus() {}};
    const control = {disabled: false};
    const trigger = {
        hidden: true, expanded: "false", focused: false,
        setAttribute(name, value) { this.expanded = value; },
        focus() { this.focused = true; }
    };
    const form = {
        hidden: false, action: "https://local.test/post/1/edit",
        querySelector(selector)
        {
            return selector === "textarea" ? textarea : status;
        },
        querySelectorAll() { return [textarea, control]; },
        closest() { return post; },
        contains() { return true; },
        setAttribute() {}, removeAttribute() {},
        reset() { textarea.value = "Original"; },
        replaceWith() { this.hidden = true; }
    };
    const old_details = [{open: true}];
    const new_details = [{open: false}];
    const body = {
        replaced: false,
        querySelectorAll() { return old_details; },
        replaceWith() { this.replaced = true; }
    };
    const edited = {replaced: false,
        replaceWith() { this.replaced = true; }};
    const post = {
        id: "p1", dataset: {},
        querySelector(selector)
        {
            return {".post-edit-form": form, ".post-body": body,
                ".post-edit-trigger": trigger, ".post-edited": edited}[selector];
        }
    };
    const updated = {
        querySelector(selector)
        {
            if(selector === ".post-edit-form")
                return {cloneNode() { return {}; }};
            return {cloneNode() { return {
                querySelectorAll() { return new_details; }
            }; }};
        }
    };
    let requests = 0;
    let resolve_request;
    let reject_request;
    const response = new Promise(function(resolve, reject)
    {
        resolve_request = resolve;
        reject_request = reject;
    });
    function fetch(url, options)
    {
        ++requests;
        assert.equal(url, form.action);
        assert.equal(options.method, "POST");
        assert.equal(options.body.get("csrf"), "token");
        assert.equal(options.body.get("content"), "My draft");
        return response;
    }
    class DOMParser
    {
        parseFromString()
        {
            return {getElementById() {
                return mode === "missing" ? null : updated;
            }};
        }
    }
    const document = {
        activeElement: textarea,
        addEventListener(name, handler) { handlers[name] = handler; },
        querySelectorAll(selector)
        {
            return selector === ".post" ? [post] : [trigger];
        }
    };
    class FormData
    {
        *[Symbol.iterator]()
        {
            yield ["content", textarea.value];
            yield ["csrf", "token"];
        }
    }
    vm.runInNewContext(source, {window: {fetch, DOMParser}, document,
        fetch, DOMParser, FormData, URLSearchParams});
    const event = {target: {closest() { return form; }}, preventDefault() {}};
    return {handlers, event, form, textarea, post, status, body, edited,
        trigger, new_details, get requests() { return requests; },
        finish() {
            if(mode === "network")
            {
                reject_request(new Error("Offline"));
                return;
            }
            resolve_request({ok: mode !== "http",
            async text() { return "post markup"; }}); }};
}

test("SaveUpdatesContentWithoutNavigationOrDuplicateRequests", async function()
{
    const state = setup("success");
    assert.equal(state.trigger.hidden, false);
    const pending = state.handlers.submit(state.event);
    assert.equal(state.textarea.disabled, true);
    await state.handlers.submit(state.event);
    assert.equal(state.requests, 1);
    state.finish();
    await pending;
    assert.equal(state.body.replaced, true);
    assert.equal(state.edited.replaced, true);
    assert.equal(state.new_details[0].open, true);
    assert.equal(state.trigger.focused, true);
    assert.equal(state.form.hidden, true);
    assert.equal(state.post.dataset.actionPending, undefined);
});

for(const mode of ["http", "missing", "network"])
{
    test("FailedSaveRetainsDraft" + mode, async function()
    {
        const state = setup(mode);
        const pending = state.handlers.submit(state.event);
        state.finish();
        await pending;
        assert.equal(state.textarea.value, "My draft");
        assert.equal(state.textarea.disabled, false);
        assert.equal(state.form.hidden, false);
        assert.equal(state.body.replaced, false);
        assert.match(state.status.textContent, /Could not confirm/);
        assert.equal(state.post.dataset.actionPending, undefined);
    });
}

test("CancelDiscardsDraftAndReturnsFocus", function()
{
    const state = setup("success");
    state.handlers.click({target: {closest() { return {
        closest() { return state.post; },
        classList: {contains() { return false; }}
    }; }}});
    assert.equal(state.form.hidden, true);
    assert.equal(state.textarea.value, "Original");
    assert.equal(state.trigger.focused, true);
    assert.equal(state.requests, 0);
});
