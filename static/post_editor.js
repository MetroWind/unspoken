(function()
{
    if(!window.fetch || !window.DOMParser) return;

    function handleClick(event)
    {
        var button = event.target.closest(
            ".post-edit-trigger, .post-edit-cancel");
        if(!button || event.defaultPrevented) return;
        var opening = button.classList.contains("post-edit-trigger");
        if(opening && (event.ctrlKey || event.metaKey || event.shiftKey
                       || event.altKey || event.button > 0)) return;
        var post = button.closest(".post");
        var form = post.querySelector(".post-edit-form");
        if(!form) return;
        event.preventDefault();
        if(post.dataset.actionPending) return;
        form.hidden = !opening;
        post.querySelector(".post-edit-trigger")
            .setAttribute("aria-expanded", String(opening));
        if(opening)
            form.querySelector("textarea").focus({preventScroll: true});
        else
        {
            form.reset();
            form.querySelector(".post-edit-status").textContent = "";
            post.querySelector(".post-edit-trigger")
                .focus({preventScroll: true});
        }
    }

    function updateCopy(post, updated)
    {
        var old_body = post.querySelector(".post-body");
        var new_body = updated.querySelector(".post-body").cloneNode(true);
        // Keep content warnings and sensitive attachments open as before.
        var old_details = old_body.querySelectorAll("details");
        new_body.querySelectorAll("details").forEach(function(details, index)
        {
            if(old_details[index]) details.open = old_details[index].open;
        });
        old_body.replaceWith(new_body);
        post.querySelector(".post-edited").replaceWith(
            updated.querySelector(".post-edited").cloneNode(true));
        post.querySelector(".post-edit-form").replaceWith(
            updated.querySelector(".post-edit-form").cloneNode(true));
        post.querySelector(".post-edit-trigger")
            .setAttribute("aria-expanded", "false");
    }

    function disableControl(control)
    {
        control.disabled = true;
    }

    function enableControl(control)
    {
        control.disabled = false;
    }

    async function handleSubmit(event)
    {
        var form = event.target.closest(".post-edit-form");
        if(!form || event.defaultPrevented) return;
        event.preventDefault();
        var post = form.closest(".post");
        if(post.dataset.actionPending) return;
        post.dataset.actionPending = "true";
        var status = form.querySelector(".post-edit-status");
        var body = new URLSearchParams(new FormData(form));
        var controls = form.querySelectorAll("input, textarea, select, button");
        controls.forEach(disableControl);
        form.setAttribute("aria-busy", "true");
        status.textContent = "Saving…";
        try
        {
            var response = await fetch(form.action, {
                method: "POST", body: body, credentials: "same-origin"
            });
            if(!response.ok) throw new Error("Save failed");
            var page = new DOMParser().parseFromString(
                await response.text(), "text/html");
            var updated = page.getElementById(post.id);
            if(!updated || !updated.querySelector(".post-edit-form"))
                throw new Error("Missing updated post");
            var restore_focus = form.contains(document.activeElement);
            document.querySelectorAll(".post").forEach(function(copy)
            {
                if(copy.id === post.id) updateCopy(copy, updated);
            });
            if(restore_focus) post.querySelector(".post-edit-trigger")
                .focus({preventScroll: true});
        }
        catch(error)
        {
            status.textContent = "Could not confirm the save. Your draft " +
                "is still here. Please check the post before trying again.";
        }
        finally
        {
            delete post.dataset.actionPending;
            controls.forEach(enableControl);
            form.removeAttribute("aria-busy");
        }
    }

    document.addEventListener("click", handleClick);
    document.addEventListener("submit", handleSubmit);
})();
