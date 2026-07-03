document.addEventListener('DOMContentLoaded', () => {
    // --- Canvas Particle Animation Background ---
    initCyberCanvas();

    // --- Password Visibility Toggle ---
    initPasswordToggles();

    // --- Password Strength Meter (Register Page) ---
    initPasswordStrengthMeter();

    // --- Auto Dismiss Flash Alerts ---
    initAlertDismissal();
});

/**
 * Initializes a futuristic digital particle network background
 */
function initCyberCanvas() {
    const canvas = document.getElementById('cyber-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    const particles = [];
    const particleCount = Math.min(60, Math.floor((width * height) / 25000)); // Responsive count
    const connectionDistance = 120;
    const baseSpeed = 0.4;

    class Particle {
        constructor() {
            this.x = Math.random() * width;
            this.y = Math.random() * height;
            this.vx = (Math.random() - 0.5) * baseSpeed;
            this.vy = (Math.random() - 0.5) * baseSpeed;
            this.radius = Math.random() * 2 + 1;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            // Bounce off edges
            if (this.x < 0 || this.x > width) this.vx = -this.vx;
            if (this.y < 0 || this.y > height) this.vy = -this.vy;
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 242, 254, 0.4)';
            ctx.shadowBlur = 4;
            ctx.shadowColor = '#00f2fe';
            ctx.fill();
            ctx.shadowBlur = 0; // Reset shadow
        }
    }

    // Populate particles
    for (let i = 0; i < particleCount; i++) {
        particles.push(new Particle());
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);

        // Draw connecting lines first
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dist = Math.hypot(particles[i].x - particles[j].x, particles[i].y - particles[j].y);
                if (dist < connectionDistance) {
                    const alpha = (1 - dist / connectionDistance) * 0.12;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(0, 242, 254, ${alpha})`;
                    ctx.lineWidth = 0.8;
                    ctx.stroke();
                }
            }
        }

        // Draw and update particles
        particles.forEach(p => {
            p.update();
            p.draw();
        });

        requestAnimationFrame(animate);
    }

    // Handle Window Resize
    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    animate();
}

/**
 * Handles password visibility toggles
 */
function initPasswordToggles() {
    const toggleButtons = document.querySelectorAll('.password-toggle-btn');
    toggleButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = btn.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            if (!passwordInput) return;

            const icon = btn.querySelector('i');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            }
        });
    });
}

/**
 * Real-time Password Strength Meter
 */
function initPasswordStrengthMeter() {
    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');

    if (!passwordInput || !strengthBar || !strengthText) return;

    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;
        let score = 0;

        if (val.length === 0) {
            updateMeter(0, '', '#ff3366');
            return;
        }

        // 1. Length rule
        if (val.length >= 8) score++;
        // 2. Uppercase letter
        if (/[A-Z]/.test(val)) score++;
        // 3. Lowercase letter
        if (/[a-z]/.test(val)) score++;
        // 4. Number
        if (/[0-9]/.test(val)) score++;
        // 5. Special character
        if (/[^A-Za-z0-9]/.test(val)) score++;

        // Map score to UX feedback
        let percentage = (score / 5) * 100;
        let label = '';
        let color = '#ff3366'; // Red for weak

        if (val.length < 8) {
            label = 'Too short (min 8 chars)';
            percentage = Math.min(percentage, 30);
        } else if (score <= 2) {
            label = 'Weak';
            color = '#ff3366';
        } else if (score === 3) {
            label = 'Medium';
            color = '#ffb300'; // Orange
        } else if (score === 4) {
            label = 'Strong';
            color = '#4facfe'; // Blue
        } else if (score === 5) {
            label = 'Secured / High Strength';
            color = '#00ffcc'; // Cyber Green
        }

        updateMeter(percentage, label, color);
        checkPasswordMatch();
    });

    if (confirmInput) {
        confirmInput.addEventListener('input', checkPasswordMatch);
    }

    function updateMeter(percentage, label, color) {
        strengthBar.style.width = `${percentage}%`;
        strengthBar.style.backgroundColor = color;
        strengthText.innerText = label;
        strengthText.style.color = color;
    }

    function checkPasswordMatch() {
        if (!confirmInput) return;
        const passVal = passwordInput.value;
        const confVal = confirmInput.value;

        if (confVal.length === 0) {
            confirmInput.classList.remove('is-valid', 'is-invalid');
            return;
        }

        if (passVal === confVal) {
            confirmInput.classList.remove('is-invalid');
            confirmInput.classList.add('is-valid');
            confirmInput.style.borderColor = '#00ffcc';
        } else {
            confirmInput.classList.remove('is-valid');
            confirmInput.classList.add('is-invalid');
            confirmInput.style.borderColor = '#ff3366';
        }
    }
}

/**
 * Automatically dismiss alerts after a few seconds
 */
function initAlertDismissal() {
    const alerts = document.querySelectorAll('.alert-cyber');
    alerts.forEach(alert => {
        setTimeout(() => {
            // Smooth fadeout
            alert.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(() => {
                alert.remove();
            }, 600);
        }, 5000); // 5 seconds
    });
}
