(function()
{
    function pad(value)
    {
        return String(value).padStart(2, "0");
    }

    function formatLocalTime(date)
    {
        return String(date.getFullYear()).padStart(4, "0") + "-" +
            pad(date.getMonth() + 1) + "-" + pad(date.getDate()) + " " +
            pad(date.getHours()) + ":" + pad(date.getMinutes());
    }

    function localize(element)
    {
        var edited = element.hasAttribute("data-edited-at");
        var timestamp = element.getAttribute(
            edited ? "data-edited-at" : "datetime");
        if(!timestamp) return;
        var date = new Date(timestamp);
        if(Number.isNaN(date.getTime())) return;
        var text = formatLocalTime(date);
        if(edited)
        {
            element.title = "Edited " + text;
            var label = element.querySelector('[role="img"]');
            if(label) label.setAttribute("aria-label", element.title);
        }
        else element.textContent = text;
    }

    var selector = "time[data-local-time], .post-edited[data-edited-at]";

    function localizeTree(root)
    {
        if(root.nodeType !== 1) return;
        if(root.matches(selector)) localize(root);
        root.querySelectorAll(selector).forEach(localize);
    }

    function handleMutations(records)
    {
        for(var record of records)
            record.addedNodes.forEach(localizeTree);
    }

    localizeTree(document.documentElement);
    // Post edits replace the edited indicator without reloading the page.
    var observer = new MutationObserver(handleMutations);
    observer.observe(document.body, {childList: true, subtree: true});
})();
