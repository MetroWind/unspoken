(function()
{
    "use strict";

    function revealPhotos()
    {
        document.querySelectorAll("img[data-photo-src]").forEach(revealPhoto);
    }

    function revealPhoto(image)
    {
        var parent = image.parentElement;
        while(parent)
        {
            if(parent.tagName === "DETAILS" && !parent.open) return;
            parent = parent.parentElement;
        }
        image.src = image.dataset.photoSrc;
        image.removeAttribute("data-photo-src");
    }

    var galleries = new Map();

    function setupGallery(gallery)
    {
        if(galleries.has(gallery)) return;
        var pip_row = gallery.parentElement.querySelector(".scroll-pips");
        var slides = Array.from(gallery.children);
        if(!pip_row || slides.length < 2) return;
        var pips = Array.from(pip_row.querySelectorAll(".scroll-pip"));
        if(pips.length !== slides.length) return;
        var active_index = -1;

        function activatePip(index)
        {
            if(active_index === index) return;
            active_index = index;
            pips.forEach(function(pip, pip_index)
            {
                var active = pip_index === index;
                pip.classList.toggle("active", active);
                if(active) pip.setAttribute("aria-current", "true");
                else pip.removeAttribute("aria-current");
            });
        }

        function galleryCenter()
        {
            return gallery.getBoundingClientRect().left + gallery.clientLeft
                + gallery.clientWidth / 2;
        }

        function slideCenter(slide)
        {
            var bounds = slide.getBoundingClientRect();
            return bounds.left + bounds.width / 2;
        }

        function scrollToPhoto(index)
        {
            var reduced_motion = typeof matchMedia === "function"
                && matchMedia("(prefers-reduced-motion: reduce)").matches;
            var left = gallery.scrollLeft + slideCenter(slides[index])
                - galleryCenter();
            gallery.scrollTo({
                left: Math.max(0, Math.min(left,
                    gallery.scrollWidth - gallery.clientWidth)),
                behavior: reduced_motion ? "auto" : "smooth"
            });
        }

        function handlePipClick(event)
        {
            scrollToPhoto(Number(event.currentTarget.dataset.photoIndex));
        }

        function handleKeydown(event)
        {
            if(event.target !== gallery) return;
            if(event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
            event.preventDefault();
            var step = event.key === "ArrowLeft" ? -1 : 1;
            scrollToPhoto(Math.max(0,
                Math.min(slides.length - 1, active_index + step)));
        }

        function updateFromPosition()
        {
            if(gallery.clientWidth <= 0) return;
            var center = galleryCenter();
            var nearest_index = 0;
            var nearest_distance = Infinity;
            slides.forEach(function(slide, index)
            {
                var distance = Math.abs(slideCenter(slide) - center);
                if(distance < nearest_distance)
                {
                    nearest_index = index;
                    nearest_distance = distance;
                }
            });
            activatePip(nearest_index);
        }

        function cleanup()
        {
            gallery.removeEventListener("scroll", updateFromPosition);
            gallery.removeEventListener("keydown", handleKeydown);
            pips.forEach(function(pip)
            {
                pip.removeEventListener("click", handlePipClick);
            });
        }

        activatePip(0);
        updateFromPosition();
        pips.forEach(function(pip)
        {
            pip.disabled = false;
            pip.addEventListener("click", handlePipClick);
        });
        gallery.addEventListener("keydown", handleKeydown);
        // Track horizontal position even when a slide is vertically clipped.
        gallery.addEventListener("scroll", updateFromPosition, {passive: true});
        galleries.set(gallery, cleanup);
    }

    function updateModeStatus(form)
    {
        var mode = form.querySelector('[name="post_kind"]');
        var input = form.querySelector('input[name="attachments"]');
        var status = form.querySelector(".photo-mode-status");
        if(!mode || !input || !status) return;
        var incompatible = Array.from(input.files).some(function(file)
        {
            return !/^(image\/(jpeg|png|gif|webp|avif|jxl))$/.test(file.type)
                && !/\.(jpe?g|png|gif|webp|avif|jxl)$/i.test(file.name);
        });
        status.textContent = mode.value === "photo" && incompatible
            ? "Some selected files may not be supported photos. Select JPEG, PNG, GIF, WebP, AVIF or JPEG XL files. Files are checked when you publish."
            : "";
    }

    function setupUploads(container)
    {
        var input = container.querySelector('input[type="file"]');
        var controls = container.querySelector(".upload-descriptions");
        if(typeof DataTransfer !== "function") return;
        var picker = input.cloneNode();
        var required = input.required;
        picker.removeAttribute("name");
        input.replaceWith(picker);
        container.appendChild(input);
        input.required = false;
        input.hidden = true;
        var entries = [];
        var form = container.closest("form");

        function syncFiles()
        {
            var transfer = new DataTransfer();
            entries.forEach(function(entry) { transfer.items.add(entry.file); });
            input.files = transfer.files;
            picker.required = required && entries.length === 0;
            updateModeStatus(form);
        }

        function revokePreview(entry)
        {
            if(entry.preview_url) URL.revokeObjectURL(entry.preview_url);
        }

        function removeEntry(index)
        {
            revokePreview(entries[index]);
            entries.splice(index, 1);
            syncFiles();
            draw();
            picker.focus();
        }

        function draw()
        {
            controls.replaceChildren();
            entries.forEach(function(entry, index)
            {
                var row = document.createElement("div");
                row.className = "upload-description";
                var label = document.createElement("label");
                label.appendChild(document.createTextNode((index + 1) + ". " + entry.file.name + " — description "));
                var description = document.createElement("input");
                description.name = "attachment_description_" + index;
                description.value = entry.description;
                description.addEventListener("input", function()
                {
                    entry.description = description.value;
                });
                label.appendChild(description);
                row.appendChild(label);
                if(entry.preview_url)
                {
                    var preview = document.createElement("img");
                    preview.className = "upload-preview";
                    preview.alt = "";
                    preview.addEventListener("error", function()
                    {
                        preview.hidden = true;
                    });
                    preview.src = entry.preview_url;
                    row.appendChild(preview);
                }
                var remove = document.createElement("button");
                remove.type = "button";
                remove.textContent = "Remove";
                remove.setAttribute("aria-label", "Remove " + entry.file.name);
                remove.addEventListener("click", function()
                {
                    removeEntry(index);
                });
                row.appendChild(remove);
                [-1, 1].forEach(function(step)
                {
                    var button = document.createElement("button");
                    button.type = "button";
                    button.textContent = step < 0 ? "Move earlier" : "Move later";
                    button.disabled = index + step < 0 || index + step >= entries.length;
                    button.addEventListener("click", function()
                    {
                        var target = index + step;
                        var swapped = entries[target];
                        entries[target] = entry;
                        entries[index] = swapped;
                        syncFiles();
                        draw();
                        controls.querySelectorAll(".upload-description")[target].querySelector("input").focus();
                    });
                    row.appendChild(button);
                });
                controls.appendChild(row);
            });
        }

        picker.addEventListener("change", function()
        {
            Array.from(picker.files).forEach(function(file)
            {
                var preview_url = "";
                if(file.type.startsWith("image/"))
                    preview_url = URL.createObjectURL(file);
                entries.push({file: file, description: "", preview_url});
            });
            picker.value = "";
            syncFiles();
            draw();
        });
        form.addEventListener("reset", function(event)
        {
            queueMicrotask(function()
            {
                if(event.defaultPrevented) return;
                entries.forEach(revokePreview);
                entries = [];
                syncFiles();
                draw();
            });
        });
        syncFiles();
        draw();
    }

    function refreshGalleries()
    {
        galleries.forEach(function(cleanup, gallery)
        {
            if(!gallery.isConnected)
            {
                cleanup();
                galleries.delete(gallery);
            }
        });
        document.querySelectorAll(".photo-post .gallery").forEach(setupGallery);
        revealPhotos();
    }

    document.addEventListener("toggle", revealPhotos, true);
    document.querySelectorAll(".photo-uploads").forEach(setupUploads);
    refreshGalleries();
    if(typeof MutationObserver !== "undefined")
        new MutationObserver(refreshGalleries).observe(document.body,
            {childList: true, subtree: true});
})();
