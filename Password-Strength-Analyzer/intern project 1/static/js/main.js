/* ==========================================================================
   INTERACTIVE CYBER AUTH GATEWAY SCRIPTS
   ========================================================================== */

document.addEventListener("DOMContentLoaded", function() {
    
    // ----------------------------------------------------------------------
    // 1. AUTO-DISMISS FLASH ALERTS
    // ----------------------------------------------------------------------
    const alerts = document.querySelectorAll('.alert-cyber');
    alerts.forEach(function(alert) {
        // Automatically trigger fade out after 6 seconds
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 6000);
    });

    // ----------------------------------------------------------------------
    // 2. REAL-TIME PASSWORD STRENGTH CHECKER & VALIDATOR (Registration Form)
    // ----------------------------------------------------------------------
    const registerForm = document.getElementById('registerForm');
    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');
    const submitBtn = document.getElementById('submitBtn');

    if (passwordInput && confirmInput && submitBtn) {
        
        // Element handlers for complexity guidelines
        const rules = {
            length: { el: document.getElementById('rule-length'), check: (val) => val.length >= 8 },
            upper: { el: document.getElementById('rule-upper'), check: (val) => /[A-Z]/.test(val) },
            lower: { el: document.getElementById('rule-lower'), check: (val) => /[a-z]/.test(val) },
            number: { el: document.getElementById('rule-number'), check: (val) => /\d/.test(val) },
            special: { el: document.getElementById('rule-special'), check: (val) => /[@$!%*?&#^()_+={}\[\]|\\:;\"'<>,.?/~`-]/.test(val) },
            match: { el: document.getElementById('rule-match'), check: (val, confirmVal) => val.length > 0 && val === confirmVal }
        };

        function validateForm() {
            const passwordVal = passwordInput.value;
            const confirmVal = confirmInput.value;
            let allValid = true;

            // Loop through rules and update UI state
            for (const key in rules) {
                const rule = rules[key];
                let isValid = false;

                if (key === 'match') {
                    isValid = rule.check(passwordVal, confirmVal);
                } else {
                    isValid = rule.check(passwordVal);
                }

                if (isValid) {
                    rule.el.classList.remove('text-danger');
                    rule.el.classList.add('text-success');
                    rule.el.querySelector('.rule-status').innerText = '[✓]';
                } else {
                    rule.el.classList.remove('text-success');
                    rule.el.classList.add('text-danger');
                    rule.el.querySelector('.rule-status').innerText = '[ ]';
                    allValid = false;
                }
            }

            // Check username constraint additionally
            const usernameInput = document.getElementById('username');
            let isUsernameValid = true;
            if (usernameInput) {
                const unVal = usernameInput.value;
                isUsernameValid = /^[a-zA-Z0-9_]{4,20}$/.test(unVal);
            }

            // Enable or disable registration submit button
            submitBtn.disabled = !(allValid && isUsernameValid);
        }

        // Bind verification listener on input keypresses
        passwordInput.addEventListener('input', validateForm);
        confirmInput.addEventListener('input', validateForm);
        
        const usernameInput = document.getElementById('username');
        if (usernameInput) {
            usernameInput.addEventListener('input', validateForm);
        }
    }

    // ----------------------------------------------------------------------
    // 3. SECURE SESSION TIMEOUT COUNTDOWN (Dashboard)
    // ----------------------------------------------------------------------
    const countdownEl = document.getElementById('session-countdown');
    if (countdownEl) {
        // 15 minutes session duration = 900 seconds
        let totalSeconds = 15 * 60;
        
        const timer = setInterval(function() {
            totalSeconds--;
            
            if (totalSeconds <= 0) {
                clearInterval(timer);
                countdownEl.innerText = "EXPIRED";
                alert("SESSION EXPIRED: For security purposes, your session has timed out. Redirecting to access gateway.");
                window.location.href = "/logout";
                return;
            }

            const minutes = Math.floor(totalSeconds / 60);
            const seconds = totalSeconds % 60;
            
            // Format minutes and seconds with leading zeroes
            const formattedMinutes = String(minutes).padStart(2, '0');
            const formattedSeconds = String(seconds).padStart(2, '0');
            
            countdownEl.innerText = `${formattedMinutes}:${formattedSeconds}`;
            
            // Turn timer red in the final minute
            if (totalSeconds < 60) {
                countdownEl.classList.remove('text-neon-pink');
                countdownEl.classList.add('text-danger');
                countdownEl.classList.add('text-blink');
            }
        }, 1000);
    }
});
