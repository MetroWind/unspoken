(function()
{
    if(!window.fetch || !window.DOMParser) return;

    function parsePage(html)
    {
        return new DOMParser().parseFromString(html, "text/html");
    }

    async function submitAction(event)
    {
        var form = event.target.closest("form[data-post-action]");
        if(!form || event.defaultPrevented) return;
        event.preventDefault();

        var post = form.closest(".post");
        if(post.dataset.actionPending) return;
        var action = form.dataset.postAction;
        var selector = 'form[data-post-action="' + action + '"]';
        var button = form.querySelector("button");
        var body = new URLSearchParams(new FormData(form));
        var error = post.querySelector(".post-action-error");
        if(error) error.remove();
        post.dataset.actionPending = "true";
        button.disabled = true;
        form.setAttribute("aria-busy", "true");

        try
        {
            var response = await fetch(form.action, {
                method: "POST",
                body: body,
                credentials: "same-origin"
            });
            if(!response.ok) throw new Error("Action failed");
            var page = parsePage(await response.text());
            var updated_post = page.getElementById(post.id);

            // A boost can move a post off the current timeline page.
            if(!updated_post || !updated_post.querySelector(selector))
            {
                response = await fetch(post.querySelector(".permalink").href,
                    {credentials: "same-origin", cache: "no-store"});
                if(!response.ok) throw new Error("Refresh failed");
                page = parsePage(await response.text());
                updated_post = page.getElementById(post.id);
            }
            var updated_form = updated_post &&
                updated_post.querySelector(selector);
            if(!updated_form) throw new Error("Missing updated action");

            var restore_focus = document.activeElement === button;
            var copies = document.querySelectorAll(".post");
            for(var copy of copies)
            {
                if(copy.id !== post.id) continue;
                var old_form = copy.querySelector(selector);
                if(!old_form) continue;
                var new_form = updated_form.cloneNode(true);
                old_form.replaceWith(new_form);
                if(copy === post && restore_focus)
                    new_form.querySelector("button").focus({preventScroll: true});
            }
        }
        catch(error)
        {
            var message = document.createElement("p");
            message.className = "post-action-error";
            message.setAttribute("role", "alert");
            message.textContent = "Could not confirm the update. " +
                "Please reload to check its status.";
            post.appendChild(message);
        }
        finally
        {
            delete post.dataset.actionPending;
            button.disabled = false;
            form.removeAttribute("aria-busy");
        }
    }

    document.addEventListener("submit", submitAction);
})();
