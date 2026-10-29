(function()
{
    var picker = document.getElementById("emoji-picker");
    if(!picker) return;

    document.documentElement.classList.add("js");
    var active_trigger = null;

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
        var choice = picker.querySelector(
            ".emoji-tab-panel.active .emoji-choice");
        if(choice) choice.focus({ preventScroll: true });
    }

    function setActiveTab(tab)
    {
        var name = tab.getAttribute("data-tab");
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
