/**
 * SHIELD // Password Analyzer & Security Dashboard
 * JavaScript Frontend Logic
 * Implements real-time analysis, debounced API requests, caps lock monitoring,
 * secure password generation, and clipboard utility.
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements - Analyzer
    const passwordInput = document.getElementById("passwordInput");
    const toggleVisibilityBtn = document.getElementById("togglePasswordVisibility");
    const toggleIcon = document.getElementById("toggleIcon");
    const charCount = document.getElementById("charCount");
    const capsWarning = document.getElementById("capsWarning");
    const strengthLabel = document.getElementById("strengthLabel");
    const strengthBar = document.getElementById("strengthBar");

    // DOM Elements - Criteria Checklist
    const critLength = document.getElementById("crit-length");
    const critUpper = document.getElementById("crit-upper");
    const critLower = document.getElementById("crit-lower");
    const critNumber = document.getElementById("crit-number");
    const critSymbol = document.getElementById("crit-symbol");

    // DOM Elements - Metrics
    const entropyVal = document.getElementById("entropyVal");
    const crackTimeVal = document.getElementById("crackTimeVal");
    const shannonVal = document.getElementById("shannonVal");
    const breachBadge = document.getElementById("breachBadge");

    // DOM Elements - Recommendations
    const suggestionsList = document.getElementById("suggestionsList");

    // DOM Elements - Generator
    const generatedPassword = document.getElementById("generatedPassword");
    const copyPasswordBtn = document.getElementById("copyPasswordBtn");
    const copySuccessMsg = document.getElementById("copySuccessMsg");
    const lengthSlider = document.getElementById("lengthSlider");
    const lengthDisplay = document.getElementById("lengthDisplay");
    const genUpper = document.getElementById("genUpper");
    const genLower = document.getElementById("genLower");
    const genNumbers = document.getElementById("genNumbers");
    const genSymbols = document.getElementById("genSymbols");
    const generatePasswordBtn = document.getElementById("generatePasswordBtn");

    let debounceTimer;

    // --- UTILITIES ---

    /**
     * Debounces a function call by a specified delay (in milliseconds).
     */
    function debounce(func, delay) {
        return function (...args) {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => func.apply(this, args), delay);
        };
    }

    /**
     * Updates check/uncheck status for a criteria item visually.
     */
    function updateCriteriaItem(element, isValid) {
        const icon = element.querySelector(".status-icon");
        if (isValid) {
            element.classList.remove("uncheck");
            element.classList.add("check");
            icon.className = "fa-solid fa-circle-check status-icon me-2 text-success";
        } else {
            element.classList.remove("check");
            element.classList.add("uncheck");
            icon.className = "fa-solid fa-circle-xmark status-icon me-2 text-danger";
        }
    }

    // --- PASSWORD EYE TOGGLE ---

    toggleVisibilityBtn.addEventListener("click", () => {
        const type = passwordInput.getAttribute("type") === "password" ? "text" : "password";
        passwordInput.setAttribute("type", type);
        
        // Toggle icon classes
        if (type === "password") {
            toggleIcon.classList.replace("fa-eye-slash", "fa-eye");
        } else {
            toggleIcon.classList.replace("fa-eye", "fa-eye-slash");
        }
    });

    // --- CAPS LOCK DETECTOR ---

    passwordInput.addEventListener("keyup", (event) => {
        if (event.getModifierState && event.getModifierState("CapsLock")) {
            capsWarning.style.display = "inline";
        } else {
            capsWarning.style.display = "none";
        }
    });

    passwordInput.addEventListener("keydown", (event) => {
        if (event.getModifierState && event.getModifierState("CapsLock")) {
            capsWarning.style.display = "inline";
        } else {
            capsWarning.style.display = "none";
        }
    });

    // --- INSTANT FRONTEND FEEDBACK ---

    /**
     * Inspects criteria using client regex immediately to make UI feel snappy.
     */
    function localCheck(pwd) {
        const hasUpper = /[A-Z]/.test(pwd);
        const hasLower = /[a-z]/.test(pwd);
        const hasDigit = /[0-9]/.test(pwd);
        const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
        const hasLength = pwd.length >= 8;

        updateCriteriaItem(critLength, hasLength);
        updateCriteriaItem(critUpper, hasUpper);
        updateCriteriaItem(critLower, hasLower);
        updateCriteriaItem(critNumber, hasDigit);
        updateCriteriaItem(critSymbol, hasSpecial);
        
        charCount.innerText = pwd.length;
    }

    // --- BACKEND ANALYSIS API CONNECTION ---

    /**
     * Makes POST request to backend API to retrieve comprehensive security metrics.
     */
    async function performBackendAnalysis(password) {
        if (!password) {
            resetAnalyzerUI();
            return;
        }

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ password: password })
            });

            if (!response.ok) {
                throw new Error("Analysis failed. Connection to cryptographic API failed.");
            }

            const data = await response.json();
            renderAnalysisResults(data);
        } catch (error) {
            console.error("Backend error:", error);
            // Graceful fallback display in case API fails
            showOfflineAnalysisResults(password);
        }
    }

    /**
     * Resets Analyzer interface values to default/empty state.
     */
    function resetAnalyzerUI() {
        charCount.innerText = "0";
        strengthLabel.innerText = "EMPTY";
        strengthLabel.className = "badge strength-badge badge-empty";
        
        strengthBar.style.width = "0%";
        strengthBar.className = "progress-bar progress-bar-striped progress-bar-animated bg-secondary";
        
        entropyVal.innerText = "0 bits";
        crackTimeVal.innerText = "Instantly";
        shannonVal.innerText = "0.00";
        
        breachBadge.innerText = "UNKNOWN";
        breachBadge.className = "badge bg-secondary";
        
        // Checklist reset
        updateCriteriaItem(critLength, false);
        updateCriteriaItem(critUpper, false);
        updateCriteriaItem(critLower, false);
        updateCriteriaItem(critNumber, false);
        updateCriteriaItem(critSymbol, false);

        // Recommendations reset
        suggestionsList.innerHTML = `
            <div class="suggestion-placeholder text-center text-muted py-4">
                <i class="fa-solid fa-circle-info fa-2x mb-2 text-cyan"></i>
                <p class="mb-0 small">Analysis engine idle. Enter a password to trigger suggestions.</p>
            </div>
        `;
    }

    /**
     * Renders API results into DOM.
     */
    function renderAnalysisResults(data) {
        // 1. Update Strength Label & Progress Bar
        strengthLabel.innerText = data.strength.toUpperCase();
        
        let barClass = "";
        let width = "0%";
        
        switch (data.strength) {
            case "Weak":
                strengthLabel.className = "badge strength-badge badge-weak";
                barClass = "progress-bar bg-danger";
                width = data.score === 0 ? "10%" : "30%";
                break;
            case "Medium":
                strengthLabel.className = "badge strength-badge badge-medium";
                barClass = "progress-bar bg-warning";
                width = data.score === 3 ? "55%" : "75%";
                break;
            case "Strong":
                strengthLabel.className = "badge strength-badge badge-strong";
                barClass = "progress-bar bg-success";
                width = "100%";
                break;
            default:
                strengthLabel.className = "badge strength-badge badge-empty";
                barClass = "progress-bar bg-secondary";
                width = "0%";
        }
        
        // Apply classes and styles
        strengthBar.className = `progress-bar progress-bar-striped progress-bar-animated ${barClass}`;
        strengthBar.style.width = width;
        strengthBar.style.boxShadow = `0 0 10px var(--cyber-${data.strength.toLowerCase()})`;

        // 2. Checklist checks (redundant backup to ensure frontend checks are in sync with API findings)
        updateCriteriaItem(critLength, data.criteria.length);
        updateCriteriaItem(critUpper, data.criteria.uppercase);
        updateCriteriaItem(critLower, data.criteria.lowercase);
        updateCriteriaItem(critNumber, data.criteria.numbers);
        updateCriteriaItem(critSymbol, data.criteria.symbols);

        // 3. Cryptographic Metrics
        entropyVal.innerText = `${data.entropy_bits} bits`;
        crackTimeVal.innerText = data.time_to_crack;
        shannonVal.innerText = data.shannon_entropy.toFixed(2);

        // Have I Been Pwned database status
        if (data.breach_status === 'breached') {
            breachBadge.innerText = `PWNED (${data.breach_count.toLocaleString()}x)`;
            breachBadge.className = "badge bg-danger text-white border border-danger shadow-sm";
        } else if (data.breach_status === 'safe') {
            breachBadge.innerText = "SECURE (0 breaches)";
            breachBadge.className = "badge bg-success text-white border border-success shadow-sm";
        } else {
            breachBadge.innerText = "OFFLINE / LIMIT";
            breachBadge.className = "badge bg-info text-dark border border-info";
        }

        // 4. Recommendation List Compilation
        if (data.suggestions && data.suggestions.length > 0) {
            suggestionsList.innerHTML = "";
            data.suggestions.forEach(suggestion => {
                const item = document.createElement("div");
                
                // Highlight breach warnings in red
                if (suggestion.includes("WARNING") || suggestion.includes("breach")) {
                    item.className = "suggestion-item danger-suggest";
                } else {
                    item.className = "suggestion-item";
                }
                
                item.innerHTML = `<i class="fa-solid fa-angle-right me-1 text-cyan"></i> ${suggestion}`;
                suggestionsList.appendChild(item);
            });
        } else {
            suggestionsList.innerHTML = `
                <div class="text-center text-success py-4">
                    <i class="fa-solid fa-circle-check fa-2x mb-2"></i>
                    <p class="mb-0 small fw-bold text-uppercase">No weaknesses detected. Excellent cryptographic configuration!</p>
                </div>
            `;
        }
    }

    /**
     * Fallback offline strength estimation if server endpoint fails.
     */
    function showOfflineAnalysisResults(pwd) {
        const hasUpper = /[A-Z]/.test(pwd);
        const hasLower = /[a-z]/.test(pwd);
        const hasDigit = /[0-9]/.test(pwd);
        const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
        const isLengthOk = pwd.length >= 8;
        
        let score = 0;
        if (isLengthOk) score++;
        if (hasUpper) score++;
        if (hasLower) score++;
        if (hasDigit) score++;
        if (hasSpecial) score++;

        // Basic offline pool size
        let pool = 0;
        if (hasLower) pool += 26;
        if (hasUpper) pool += 26;
        if (hasDigit) pool += 10;
        if (hasSpecial) pool += 33;

        const entropy = pool > 0 ? Math.round(pwd.length * Math.log2(pool)) : 0;
        entropyVal.innerText = `${entropy} bits (Offline)`;
        shannonVal.innerText = "N/A";
        crackTimeVal.innerText = entropy >= 60 ? "Centuries" : (entropy >= 35 ? "Days" : "Instantly");
        breachBadge.innerText = "API ERROR";
        breachBadge.className = "badge bg-warning text-dark";

        // basic strength
        let strength = "Weak";
        let barClass = "progress-bar bg-danger";
        let width = "30%";

        if (score >= 5 && entropy >= 50) {
            strength = "Strong";
            barClass = "progress-bar bg-success";
            width = "100%";
        } else if (score >= 3) {
            strength = "Medium";
            barClass = "progress-bar bg-warning";
            width = "60%";
        }

        strengthLabel.innerText = strength.toUpperCase();
        strengthLabel.className = `badge strength-badge badge-${strength.toLowerCase()}`;
        strengthBar.className = `progress-bar progress-bar-striped progress-bar-animated ${barClass}`;
        strengthBar.style.width = width;

        suggestionsList.innerHTML = `
            <div class="suggestion-item">
                <i class="fa-solid fa-circle-exclamation text-warning me-1"></i> Analysis is running in offline mode. Suggestions and breach checker require connection to Flask backend.
            </div>
        `;
    }

    // Attach listener with debouncer to avoid excessive API requests
    passwordInput.addEventListener("input", (e) => {
        const pwd = e.target.value;
        localCheck(pwd);
        
        // Debounce backend check by 200ms
        debounce(() => {
            performBackendAnalysis(pwd);
        }, 200)();
    });


    // --- PASSWORD GENERATOR ---

    // Slider range update
    lengthSlider.addEventListener("input", (e) => {
        lengthDisplay.innerText = e.target.value;
    });

    /**
     * Securely generates custom password from backend API generator
     */
    async function generateSecurePassword() {
        const len = lengthSlider.value;
        const upper = genUpper.checked;
        const lower = genLower.checked;
        const numbers = genNumbers.checked;
        const symbols = genSymbols.checked;

        // Visual loading state
        generatedPassword.value = "CONNECTING INTEGRITY ALGORITHM...";
        generatePasswordBtn.disabled = true;

        try {
            const queryUrl = `/api/generate?length=${len}&uppercase=${upper}&lowercase=${lower}&numbers=${numbers}&symbols=${symbols}`;
            const response = await fetch(queryUrl);
            
            if (!response.ok) {
                throw new Error("Unable to contact generation engine.");
            }

            const data = await response.json();
            generatedPassword.value = data.password;
            
            // Enable Clipboard Copy
            copyPasswordBtn.disabled = false;
        } catch (error) {
            console.error("Generator failed:", error);
            // Client side fallback generator
            generatedPassword.value = fallbackClientGenerator(len, upper, lower, numbers, symbols);
            copyPasswordBtn.disabled = false;
        } finally {
            generatePasswordBtn.disabled = false;
        }
    }

    /**
     * Fallback random string generation on client-side if API goes down
     */
    function fallbackClientGenerator(len, upper, lower, numbers, symbols) {
        let pool = "";
        let result = [];
        
        if (upper) { pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; result.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ"[Math.floor(Math.random() * 26)]); }
        if (lower) { pool += "abcdefghijklmnopqrstuvwxyz"; result.push("abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)]); }
        if (numbers) { pool += "0123456789"; result.push("0123456789"[Math.floor(Math.random() * 10)]); }
        if (symbols) { pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"; result.push("!@#$%^&*()_+-=[]{}|;:,.<>?"[Math.floor(Math.random() * 25)]); }

        if (pool === "") {
            pool = "abcdefghijklmnopqrstuvwxyz1234567890";
        }

        while (result.length < len) {
            result.push(pool[Math.floor(Math.random() * pool.length)]);
        }

        // Shuffle
        result.sort(() => Math.random() - 0.5);
        return result.slice(0, len).join("");
    }

    // Bind generator click event
    generatePasswordBtn.addEventListener("click", generateSecurePassword);

    // --- COPY TO CLIPBOARD ---

    copyPasswordBtn.addEventListener("click", () => {
        const textToCopy = generatedPassword.value;
        if (!textToCopy || textToCopy.startsWith("CONNECTING")) return;

        navigator.clipboard.writeText(textToCopy)
            .then(() => {
                // Show Success Message
                copySuccessMsg.style.display = "block";
                
                // Pulse copy button visually
                copyPasswordBtn.classList.remove("text-cyan");
                copyPasswordBtn.classList.add("text-success");
                
                setTimeout(() => {
                    copySuccessMsg.style.display = "none";
                    copyPasswordBtn.classList.remove("text-success");
                    copyPasswordBtn.classList.add("text-cyan");
                }, 2000);
            })
            .catch(err => {
                console.error("Clipboard copy failed:", err);
            });
    });
});
