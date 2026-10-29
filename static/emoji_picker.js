(function()
{
    var picker = document.getElementById("emoji-picker");
    if(!picker) return;

    document.documentElement.classList.add("js");
    var active_trigger = null;
    var load_promise = null;
    var categories = [];
    var panels = [];

    function createNode(tag, class_name, text)
    {
        var node = document.createElement(tag);
        node.className = class_name;
        if(text !== undefined) node.textContent = text;
        return node;
    }

    function createChoice(value, name, image_url)
    {
        var button = createNode("button", "emoji-choice");
        button.type = "button";
        button.setAttribute("data-emoji-insert", value);
        button.title = name;
        button.setAttribute("aria-label", "Choose " + name);
        if(image_url)
        {
            var image = createNode("img", "emoji");
            image.src = image_url;
            image.alt = value;
            image.loading = "lazy";
            button.append(image);
        }
        else button.textContent = value;
        return button;
    }

    function buildCategory(index)
    {
        if(panels[index]) return;
        var category = categories[index];
        var panel = createNode("div", "emoji-tab-panel");
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("data-tab-panel", String(index));
        if(category.custom)
        {
            var custom_grid = createNode("div", "emoji-grid");
            for(var item of category.custom)
            {
                var shortcode = ":" + item.shortcode + ":";
                custom_grid.append(createChoice(
                    shortcode, shortcode, item.image_url));
            }
            panel.append(custom_grid);
        }
        else
        {
            for(var subgroup of category.subgroups)
            {
                var section = createNode("div", "emoji-subgroup");
                section.append(createNode(
                    "div", "emoji-subgroup-label", subgroup.label));
                var grid = createNode("div", "emoji-grid");
                for(var entry of subgroup.emoji)
                {
                    grid.append(createChoice(entry.emoji, entry.name));
                }
                section.append(grid);
                panel.append(section);
            }
        }
        panels[index] = panel;
        picker.append(panel);
    }

    function buildCatalog(data)
    {
        categories = [];
        panels = [];
        if(data.custom.length)
        {
            categories.push({label: "Custom", representative_emoji: "custom",
                custom: data.custom});
        }
        categories.push(...data.categories);
        picker.replaceChildren();
        if(!categories.length)
        {
            picker.append(createNode("p", "hint", "No emoji available."));
            return;
        }
        var tabs = createNode("div", "emoji-tabs");
        tabs.setAttribute("role", "tablist");
        for(var index = 0; index < categories.length; ++index)
        {
            var category = categories[index];
            var tab = createNode("button", "emoji-tab",
                category.representative_emoji);
            tab.type = "button";
            tab.setAttribute("role", "tab");
            tab.setAttribute("data-tab", String(index));
            tab.setAttribute("aria-label", category.label);
            tab.title = category.label;
            tabs.append(tab);
        }
        picker.append(tabs);
        setActiveTab(tabs.firstElementChild);
    }

    async function loadCatalog()
    {
        picker.replaceChildren(createNode("p", "hint", "Loading emoji…"));
        picker.setAttribute("aria-busy", "true");
        try
        {
            var response = await fetch(picker.getAttribute("data-catalog-url"));
            if(!response.ok) throw new Error("Emoji catalog unavailable");
            buildCatalog(await response.json());
        }
        finally
        {
            picker.setAttribute("aria-busy", "false");
        }
    }

    async function refreshPicker(trigger)
    {
        try
        {
            if(!load_promise) load_promise = loadCatalog();
            await load_promise;
            if(active_trigger !== trigger) return;
            positionPicker();
            var choice = picker.querySelector(
                ".emoji-tab-panel.active .emoji-choice");
            if(choice) choice.focus({ preventScroll: true });
        }
        catch(error)
        {
            load_promise = null;
            var message = createNode("p", "hint", "Could not load emoji.");
            message.setAttribute("role", "status");
            var retry = createNode("button", "linkbtn", "Retry");
            retry.type = "button";
            retry.setAttribute("data-emoji-retry", "true");
            picker.replaceChildren(message, retry);
            positionPicker();
        }
    }

    function closePicker(restore_focus)
    {
        picker.hidden = true;
        if(!active_trigger) return;
        active_trigger.setAttribute("aria-expanded", "false");
        if(restore_focus) active_trigger.focus();
        active_trigger = null;
    }

    function positionPicker()
    {
        if(!active_trigger) return;
        var rect = active_trigger.getBoundingClientRect();
        var width = picker.offsetWidth;
        var height = picker.offsetHeight;
        var left = Math.max(12, Math.min(rect.left,
            window.innerWidth - width - 12));
        var top = rect.bottom + 4;
        if(top + height > window.innerHeight - 12)
        {
            top = Math.max(12, rect.top - height - 4);
        }
        picker.style.left = left + "px";
        picker.style.top = top + "px";
    }

    function openPicker(trigger)
    {
        if(active_trigger === trigger)
        {
            closePicker(true);
            return;
        }
        closePicker(false);
        active_trigger = trigger;
        trigger.setAttribute("aria-expanded", "true");
        picker.setAttribute("aria-label",
            trigger.getAttribute("data-emoji-mode") === "react"
                ? "React with an emoji" : "Insert an emoji");
        picker.hidden = false;
        positionPicker();
        refreshPicker(trigger);
    }

    function setActiveTab(tab)
    {
        var name = tab.getAttribute("data-tab");
        buildCategory(Number(name));
        picker.querySelectorAll(".emoji-tab").forEach(function(item)
        {
            var active = item === tab;
            item.classList.toggle("active", active);
            item.setAttribute("aria-selected", active ? "true" : "false");
        });
        picker.querySelectorAll(".emoji-tab-panel").forEach(function(panel)
        {
            var active = panel.getAttribute("data-tab-panel") === name;
            panel.classList.toggle("active", active);
        });
        positionPicker();
    }

    function chooseEmoji(button)
    {
        if(!active_trigger) return;
        var value = button.getAttribute("data-emoji-insert");
        var form = active_trigger.closest("form");
        if(!value || !form) return;

        if(active_trigger.getAttribute("data-emoji-mode") === "react")
        {
            form.querySelector("input[name='emoji']").value = value;
            closePicker(true);
            form.requestSubmit();
            return;
        }

        var textarea = form.querySelector("textarea[name='content']");
        if(!textarea) return;
        var start = textarea.selectionStart;
        var end = textarea.selectionEnd;
        textarea.setRangeText(value, start, end, "end");
        closePicker(false);
        textarea.focus();
        textarea.dispatchEvent(new Event("input", { bubbles: true }));
    }

    function handleClick(event)
    {
        var trigger = event.target.closest(".emoji-picker-trigger");
        if(trigger)
        {
            openPicker(trigger);
            return;
        }
        if(!picker.contains(event.target))
        {
            closePicker(false);
            return;
        }
        if(event.target.closest("[data-emoji-retry]"))
        {
            refreshPicker(active_trigger);
            return;
        }
        var tab = event.target.closest(".emoji-tab");
        if(tab) setActiveTab(tab);
        var choice = event.target.closest(".emoji-choice");
        if(choice) chooseEmoji(choice);
    }

    function handleKeydown(event)
    {
        if(event.key === "Escape" && active_trigger)
        {
            event.preventDefault();
            closePicker(true);
        }
    }

    function handleFocus(event)
    {
        if(active_trigger && event.target !== active_trigger
           && !picker.contains(event.target))
        {
            closePicker(false);
        }
    }

    function enableTrigger(trigger)
    {
        trigger.hidden = false;
    }

    document.querySelectorAll(".emoji-picker-trigger").forEach(enableTrigger);
    document.addEventListener("click", handleClick);
    document.addEventListener("keydown", handleKeydown);
    document.addEventListener("focusin", handleFocus);
    window.addEventListener("resize", positionPicker);
    document.addEventListener("scroll", positionPicker, true);
})();
