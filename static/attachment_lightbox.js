(function()
{
    var dialog = document.getElementById("attachment-lightbox");
    if(!dialog || typeof dialog.showModal !== "function") return;

    var image = dialog.querySelector(".lightbox-image");
    var previous = dialog.querySelector(".lightbox-previous");
    var next = dialog.querySelector(".lightbox-next");
    var status = dialog.querySelector(".lightbox-status");
    var links = [];
    var index = 0;
    var trigger = null;

    function showImage(new_index)
    {
        index = (new_index + links.length) % links.length;
        image.src = links[index].href;
        image.alt = links[index].querySelector("img").alt;
        previous.hidden = next.hidden = links.length < 2;
        status.textContent = (index + 1) + " / " + links.length;
    }

    function openImage(event)
    {
        if(event.defaultPrevented || event.button !== 0 || event.ctrlKey ||
           event.metaKey || event.shiftKey || event.altKey) return;
        var link = event.target.closest(".attachments a");
        if(!link || !link.querySelector("img")) return;
        links = Array.from(link.closest(".attachments").querySelectorAll("a"))
            .filter(hasImage);
        trigger = link;
        showImage(links.indexOf(link));
        dialog.showModal();
        document.documentElement.classList.add("lightbox-open");
        event.preventDefault();
    }

    function hasImage(link)
    {
        return link.querySelector("img") !== null;
    }

    function closeImage()
    {
        dialog.close();
    }

    function previousImage()
    {
        showImage(index - 1);
    }

    function nextImage()
    {
        showImage(index + 1);
    }

    function handleKeydown(event)
    {
        if(event.key === "ArrowLeft" || event.key === "ArrowRight")
        {
            event.preventDefault();
            showImage(index + (event.key === "ArrowLeft" ? -1 : 1));
        }
    }

    function handleBackdrop(event)
    {
        if(event.target === dialog) closeImage();
    }

    function restorePage()
    {
        document.documentElement.classList.remove("lightbox-open");
        image.removeAttribute("src");
        image.alt = "";
        if(trigger) trigger.focus();
    }

    document.addEventListener("click", openImage);
    dialog.querySelector(".lightbox-close").addEventListener("click", closeImage);
    previous.addEventListener("click", previousImage);
    next.addEventListener("click", nextImage);
    dialog.addEventListener("keydown", handleKeydown);
    dialog.addEventListener("click", handleBackdrop);
    dialog.addEventListener("close", restorePage);
})();
