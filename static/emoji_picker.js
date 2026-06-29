(function() {
    document.documentElement.classList.add("js");

    function setActiveTab(picker, tab) {
        var name = tab.getAttribute("data-tab");
        picker.querySelectorAll(".emoji-tab").forEach(function(item) {
            var active = item === tab;
            item.classList.toggle("active", active);
            item.setAttribute("aria-selected", active ? "true" : "false");
        });
        picker.querySelectorAll(".emoji-tab-panel").forEach(function(panel) {
            var active = panel.getAttribute("data-tab-panel") === name;
            panel.classList.toggle("active", active);
        });
    }

    function insertValue(button) {
        var value = button.getAttribute("data-emoji-insert");
        if(!value) return;

        var picker = button.closest(".emoji-picker");
        if(!picker) return;
        var form = picker.closest("form");
        if(!form) return;
        var textarea = form.querySelector("textarea[name='content']");
        if(!textarea) return;

        if(typeof textarea.selectionStart !== "number") {
            textarea.value += value;
            textarea.focus();
            textarea.dispatchEvent(new Event("input", { bubbles: true }));
            return;
        }

        var start = textarea.selectionStart;
        var end = textarea.selectionEnd;
        var before = textarea.value.slice(0, start);
        var after = textarea.value.slice(end);
        textarea.value = before + value + after;
        var cursor = before.length + value.length;
        textarea.setSelectionRange(cursor, cursor);
        textarea.focus();
        textarea.dispatchEvent(new Event("input", { bubbles: true }));
    }

    document.querySelectorAll(".emoji-picker").forEach(function(picker) {
        picker.querySelectorAll(".emoji-tab").forEach(function(tab) {
            tab.addEventListener("click", function() {
                setActiveTab(picker, tab);
            });
        });

        if(picker.getAttribute("data-emoji-mode") === "insert") {
            picker.querySelectorAll(".emoji-choice").forEach(function(button) {
                button.addEventListener("click", function() {
                    insertValue(button);
                });
            });
        }
    });
})();
