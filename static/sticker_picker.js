(function()
{
    "use strict";
    var script = document.currentScript;
    if(!script || !window.fetch || !window.HTMLDialogElement) return;
    var endpoint = script.dataset.catalog;
    var catalog;
    var dialog = document.createElement("dialog");
    dialog.className = "sticker-picker";
    dialog.setAttribute("aria-label", "Choose a sticker");
    var tabs = document.createElement("div");
    tabs.className = "sticker-tabs";
    tabs.setAttribute("role", "tablist");
    var grid = document.createElement("div");
    grid.className = "sticker-grid";
    grid.setAttribute("role", "tabpanel");
    grid.id = "sticker-panel";
    var status = document.createElement("p");
    status.setAttribute("role", "status");
    var close = document.createElement("button");
    close.type = "button";
    close.textContent = "Close";
    dialog.append(tabs, grid, status, close);
    document.body.append(dialog);
    var active_form;
    var trigger;
    var packs;
    var originals = new WeakMap();

    function remember(form)
    {
        if(originals.has(form)) return;
        var image = form.querySelector(".sticker-preview");
        originals.set(form, {
            src: image.getAttribute("src"), alt: image.alt,
            hidden: form.querySelector(".sticker-selection").hidden
        });
    }

    function restore(form)
    {
        var original = originals.get(form);
        if(!original) return;
        var image = form.querySelector(".sticker-preview");
        if(original.src) image.src = original.src;
        else image.removeAttribute("src");
        image.alt = original.alt;
        form.querySelector(".sticker-selection").hidden = original.hidden;
    }

    function closePicker()
    {
        dialog.close();
    }

    function returnFocus()
    {
        if(trigger && trigger.isConnected)
        {
            trigger.setAttribute("aria-expanded", "false");
            trigger.focus();
        }
    }

    function choose(event)
    {
        var button = event.target.closest("[data-sticker-index]");
        if(!button) return;
        var sticker = packs[Number(grid.dataset.pack)]
            .stickers[Number(button.dataset.stickerIndex)];
        active_form.elements.sticker_action.value = "set";
        active_form.elements.sticker.value = sticker.key;
        var image = active_form.querySelector(".sticker-preview");
        image.src = sticker.url;
        image.alt = sticker.name;
        active_form.querySelector(".sticker-selection").hidden = false;
        closePicker();
    }

    function showPack(index)
    {
        grid.replaceChildren();
        grid.dataset.pack = String(index);
        var children = tabs.querySelectorAll("button");
        children.forEach(function(tab, position)
        {
            tab.setAttribute("aria-selected", String(position === index));
            tab.tabIndex = position === index ? 0 : -1;
        });
        grid.setAttribute("aria-labelledby", children[index].id);
        packs[index].stickers.forEach(function(sticker, position)
        {
            var button = document.createElement("button");
            button.type = "button";
            button.dataset.stickerIndex = String(position);
            button.setAttribute("aria-label", sticker.name);
            button.setAttribute("aria-pressed",
                String(active_form.elements.sticker.value === sticker.key));
            var image = document.createElement("img");
            image.src = sticker.url;
            image.alt = sticker.name;
            image.loading = "lazy";
            button.append(image);
            grid.append(button);
        });
    }

    function selectTab(event)
    {
        var button = event.target.closest("[data-pack-index]");
        if(button) showPack(Number(button.dataset.packIndex));
    }

    function tabKey(event)
    {
        var button = event.target.closest("[data-pack-index]");
        if(!button) return;
        var index = Number(button.dataset.packIndex);
        if(event.key === "ArrowRight") index = (index + 1) % packs.length;
        else if(event.key === "ArrowLeft")
            index = (index + packs.length - 1) % packs.length;
        else if(event.key === "Home") index = 0;
        else if(event.key === "End") index = packs.length - 1;
        else return;
        event.preventDefault();
        showPack(index);
        tabs.children[index].focus();
    }

    async function loadCatalog()
    {
        var response = await fetch(endpoint, {credentials: "same-origin"});
        if(!response.ok) throw new Error("Catalog unavailable");
        return response.json();
    }

    async function handleClick(event)
    {
        var button = event.target.closest(
            ".sticker-picker-trigger, .sticker-remove");
        if(!button) return;
        var form = button.closest("form");
        remember(form);
        if(button.classList.contains("sticker-remove"))
        {
            form.elements.sticker_action.value = "clear";
            form.elements.sticker.value = "";
            form.querySelector(".sticker-selection").hidden = true;
            return;
        }
        active_form = form;
        trigger = button;
        trigger.setAttribute("aria-expanded", "true");
        status.textContent = "Loading…";
        tabs.replaceChildren();
        grid.replaceChildren();
        dialog.showModal();
        try
        {
            if(!catalog) catalog = loadCatalog();
            packs = await catalog;
            // The user may close or open another form while loading.
            if(!dialog.open || active_form !== form) return;
            packs.forEach(function(pack, index)
            {
                var tab = document.createElement("button");
                tab.type = "button";
                tab.textContent = pack.name;
                tab.id = "sticker-tab-" + index;
                tab.dataset.packIndex = String(index);
                tab.setAttribute("role", "tab");
                tab.setAttribute("aria-controls", grid.id);
                tabs.append(tab);
            });
            status.textContent = packs.length ? "" : "No stickers available.";
            if(packs.length)
            {
                showPack(0);
                tabs.firstElementChild.focus();
            }
        }
        catch(error)
        {
            status.textContent = "Could not load stickers. Refresh the page.";
        }
    }

    function handleReset(event)
    {
        restore(event.target);
    }

    function enableTriggers(root)
    {
        root.querySelectorAll(".sticker-picker-trigger").forEach(function(button)
        {
            button.hidden = false;
        });
    }

    close.addEventListener("click", closePicker);
    dialog.addEventListener("close", returnFocus);
    grid.addEventListener("click", choose);
    tabs.addEventListener("click", selectTab);
    tabs.addEventListener("keydown", tabKey);
    document.addEventListener("click", handleClick);
    document.addEventListener("reset", handleReset);
    enableTriggers(document);
    var observer = new MutationObserver(function(records)
    {
        records.forEach(function(record)
        {
            record.addedNodes.forEach(function(node)
            {
                if(node.nodeType === 1) enableTriggers(node);
            });
        });
    });
    observer.observe(document.body, {childList: true, subtree: true});
})();
