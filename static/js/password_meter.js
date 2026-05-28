/**
 * password_meter.js
 * Client-side password strength meter
 * Checks: length, uppercase, lowercase, digit, symbol
 */

/**
 * Evaluate password and return which rules pass.
 * @param {string} password
 * @returns {object} - boolean flags for each requirement
 */
function evaluatePassword(password) {
    return {
        min_length: password.length >= 12,
        uppercase:  /[A-Z]/.test(password),
        lowercase:  /[a-z]/.test(password),
        digit:      /\d/.test(password),
        symbol:     /[!@#$%^&*()\-_=+\[\]{};':"\\|,.<>\/?`~]/.test(password),
    };
}

/**
 * Calculate strength label and fill percentage from passed checks.
 * @param {object} checks - result of evaluatePassword()
 * @returns {{ label: string, percent: number, color: string }}
 */
function calcStrength(checks) {
    const score = Object.values(checks).filter(Boolean).length;

    if (score <= 2) return { label: "Weak",   percent: 33,  color: "#ff4757" };
    if (score <= 4) return { label: "Medium", percent: 66,  color: "#ffa502" };
    return              { label: "Strong", percent: 100, color: "#00ff88" };
}

/**
 * Called on every keystroke in the password field.
 * Updates the meter bar, label, and requirement checklist.
 * @param {string} value - current password input value
 */
function updateStrength(value) {
    const checks   = evaluatePassword(value);
    const strength = calcStrength(checks);

    // Update meter bar
    const fill  = document.getElementById("meter-fill");
    const label = document.getElementById("meter-label");

    fill.style.width      = value.length === 0 ? "0%" : strength.percent + "%";
    fill.style.background = strength.color;
    label.textContent     = value.length === 0 ? "—" : strength.label;
    label.style.color     = strength.color;

    // Update each requirement list item
    const map = {
        "req-length": checks.min_length,
        "req-upper":  checks.uppercase,
        "req-lower":  checks.lowercase,
        "req-digit":  checks.digit,
        "req-symbol": checks.symbol,
    };

    for (const [id, passed] of Object.entries(map)) {
        const el = document.getElementById(id);
        if (el) el.classList.toggle("pass", passed);
    }

    // Also recheck the confirm match while typing
    checkMatch();
}

/**
 * Called on every keystroke in the confirm password field.
 * Shows a match / no-match indicator.
 */
function checkMatch() {
    const pw      = document.getElementById("password");
    const confirm = document.getElementById("confirm_password");
    const msg     = document.getElementById("match-msg");

    if (!pw || !confirm || !msg) return;

    if (confirm.value.length === 0) {
        msg.textContent = "";
        msg.className   = "match-msg";
        return;
    }

    if (pw.value === confirm.value) {
        msg.textContent = "✓ Passwords match";
        msg.className   = "match-msg ok";
    } else {
        msg.textContent = "✗ Passwords do not match";
        msg.className   = "match-msg fail";
    }
}

/**
 * Toggle password visibility for a given input field ID.
 * @param {string} fieldId - the ID of the input field
 */
function toggleVisibility(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
}
