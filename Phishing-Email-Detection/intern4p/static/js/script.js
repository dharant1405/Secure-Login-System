/**
 * Cybersecurity Authentication System - JS Functionality
 * Theme: Cyberpunk Anime
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- 1. PREVENT PAGE LOADER OVERLAY FROM HANGING ---
    const loader = document.getElementById('loading-overlay');
    if (loader) {
        window.addEventListener('load', () => {
            setTimeout(() => {
                loader.classList.add('loading-hide');
            }, 600);
        });

        // Fallback: hide if window.load already fired or is delayed
        setTimeout(() => {
            loader.classList.add('loading-hide');
        }, 1500);
    }

    // --- 2. CANVAS RAIN EFFECT ---
    const rainCanvas = document.getElementById('rain-canvas');
    if (rainCanvas) {
        const ctx = rainCanvas.getContext('2d');
        let width = (rainCanvas.width = window.innerWidth);
        let height = (rainCanvas.height = window.innerHeight);

        window.addEventListener('resize', () => {
            width = (rainCanvas.width = window.innerWidth);
            height = (rainCanvas.height = window.innerHeight);
        });

        const columns = Math.floor(width / 20);
        const yPositions = Array(columns).fill(0);

        function drawRain() {
            // Semi-transparent black block to create trailing blur effect
            ctx.fillStyle = 'rgba(7, 7, 12, 0.08)';
            ctx.fillRect(0, 0, width, height);

            ctx.fillStyle = '#00f0ff'; // Cyber neon blue rain drops
            ctx.font = '15px monospace';

            for (let i = 0; i < yPositions.length; i++) {
                // Generate random characters
                const charCode = 33 + Math.floor(Math.random() * 93);
                const char = String.fromCharCode(charCode);
                const x = i * 20;
                const y = yPositions[i];

                ctx.fillText(char, x, y);

                if (y > height && Math.random() > 0.975) {
                    yPositions[i] = 0;
                } else {
                    yPositions[i] += 15;
                }
            }
        }

        setInterval(drawRain, 50);
    }

    // --- 3. CANVAS PARTICLE SYSTEM ---
    const particleCanvas = document.getElementById('particle-canvas');
    if (particleCanvas) {
        const ctx = particleCanvas.getContext('2d');
        let w = (particleCanvas.width = window.innerWidth);
        let h = (particleCanvas.height = window.innerHeight);

        window.addEventListener('resize', () => {
            w = (particleCanvas.width = window.innerWidth);
            h = (particleCanvas.height = window.innerHeight);
        });

        const particles = [];
        const maxParticles = 60;

        class Particle {
            constructor() {
                this.x = Math.random() * w;
                this.y = Math.random() * h;
                this.size = Math.random() * 2.5 + 0.5;
                this.speedX = Math.random() * 0.6 - 0.3;
                this.speedY = Math.random() * 0.6 - 0.3;
                // Alternate particle glow colors
                this.color = Math.random() > 0.5 ? 'rgba(0, 240, 255, 0.3)' : 'rgba(189, 0, 255, 0.3)';
            }

            update() {
                this.x += this.speedX;
                this.y += this.speedY;

                if (this.x < 0 || this.x > w) this.speedX *= -1;
                if (this.y < 0 || this.y > h) this.speedY *= -1;
            }

            draw() {
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                ctx.fillStyle = this.color;
                ctx.shadowBlur = 8;
                ctx.shadowColor = this.color;
                ctx.fill();
                ctx.shadowBlur = 0; // Reset
            }
        }

        // Initialize particles
        for (let i = 0; i < maxParticles; i++) {
            particles.push(new Particle());
        }

        function animateParticles() {
            ctx.clearRect(0, 0, w, h);

            // Draw connections
            for (let a = 0; a < particles.length; a++) {
                for (let b = a + 1; b < particles.length; b++) {
                    const dx = particles[a].x - particles[b].x;
                    const dy = particles[a].y - particles[b].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 120) {
                        ctx.beginPath();
                        ctx.moveTo(particles[a].x, particles[a].y);
                        ctx.lineTo(particles[b].x, particles[b].y);
                        ctx.strokeStyle = `rgba(189, 0, 255, ${0.15 - dist / 120 / 8})`;
                        ctx.lineWidth = 0.5;
                        ctx.stroke();
                    }
                }
            }

            particles.forEach(p => {
                p.update();
                p.draw();
            });

            requestAnimationFrame(animateParticles);
        }

        animateParticles();
    }

    // --- 4. TYPING EFFECTS FOR THE TERMINAL ---
    const terminalElement = document.querySelector('.cyber-terminal-text');
    if (terminalElement) {
        const messages = [
            "SYS_INIT: Booting Secure Portal Core...",
            "DB_CONN: Uplink established with local SQLITE node.",
            "SEC_WARN: Activating Session Sanitizers and CSRF Firewalls.",
            "AUDIT: Checking connection node details...",
            "STATUS: Connection IP: " + (window.location.hostname || "127.0.0.1") + " authenticated.",
            "Ready for credential handshakes. Awaiting uplink command."
        ];
        
        let messageIndex = 0;
        let charIndex = 0;
        let currentText = "";
        
        function typeMessage() {
            if (messageIndex < messages.length) {
                const targetMsg = messages[messageIndex];
                
                if (charIndex < targetMsg.length) {
                    currentText += targetMsg.charAt(charIndex);
                    // Add cursor element dynamically
                    terminalElement.innerHTML = currentText + '<span class="typing-cursor"></span>';
                    charIndex++;
                    setTimeout(typeMessage, 20 + Math.random() * 15);
                } else {
                    currentText += "<br>";
                    charIndex = 0;
                    messageIndex++;
                    setTimeout(typeMessage, 450);
                }
            }
        }
        
        setTimeout(typeMessage, 800);
    }

    // --- 5. PASSWORD STRENGTH METER CALCULATION ---
    const passwordInput = document.getElementById('password');
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');

    if (passwordInput && strengthBar && strengthText) {
        passwordInput.addEventListener('input', () => {
            const val = passwordInput.value;
            let score = 0;

            if (val.length === 0) {
                strengthBar.style.width = '0%';
                strengthBar.className = 'progress-bar-cyber';
                strengthText.textContent = 'None';
                return;
            }

            // Evaluation Criteria
            const criteria = {
                length: val.length >= 8,
                lowercase: /[a-z]/.test(val),
                uppercase: /[A-Z]/.test(val),
                number: /[0-9]/.test(val),
                special: /[_@$!%*?&+-]/.test(val)
            };

            // Count completed criteria
            score = Object.values(criteria).filter(Boolean).length;

            let percentage = (score / 5) * 100;
            strengthBar.style.width = `${percentage}%`;

            // Reset classes
            strengthBar.className = 'progress-bar-cyber';

            if (score <= 2) {
                strengthBar.classList.add('strength-weak');
                strengthText.textContent = 'Weak';
                strengthText.style.color = '#ff0055';
            } else if (score === 3) {
                strengthBar.classList.add('strength-medium');
                strengthText.textContent = 'Medium';
                strengthText.style.color = '#ffaa00';
            } else if (score === 4) {
                strengthBar.classList.add('strength-strong');
                strengthText.textContent = 'Strong';
                strengthText.style.color = '#adff2f';
            } else if (score === 5) {
                strengthBar.classList.add('strength-very-strong');
                strengthText.textContent = 'Very Strong';
                strengthText.style.color = '#00ff66';
            }
        });
    }
});
