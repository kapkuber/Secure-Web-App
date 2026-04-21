"use strict";

// Client side password confirmation check
(function () {
    const form = document.querySelector("form");
    const pw   = document.getElementById("password");
    const conf = document.getElementById("confirm_password");

    if (form && pw && conf) {
        form.addEventListener("submit", function (e) {
            if (pw.value !== conf.value) {
                e.preventDefault();
                alert("Passwords do not match.");
                conf.focus();
            }
        });
    }
})();

// Auto dismiss flash messages after 5 seconds
(function () {
    const flashes = document.querySelectorAll(".flash");
    flashes.forEach(function (el) {
        setTimeout(function () {
            el.style.transition = "opacity 0.5s";
            el.style.opacity    = "0";
            setTimeout(function () { el.remove(); }, 500);
        }, 5000);
    });
})();
