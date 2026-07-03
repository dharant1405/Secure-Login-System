document.addEventListener('DOMContentLoaded', function () {
    const analyzerForm = document.getElementById('email-analyzer-form');
    const emailInput = document.getElementById('email_content');
    const analyzeBtn = document.getElementById('analyze-btn');
    
    // Result panels
    const defaultPlaceholder = document.getElementById('default-placeholder');
    const resultBox = document.getElementById('result-box');
    const resultText = document.getElementById('result-text');
    const confidenceText = document.getElementById('confidence-text');
    const confidenceBar = document.getElementById('confidence-bar');
    const textPreview = document.getElementById('text-preview');
    
    // Recommendations
    const recsContainer = document.getElementById('recs-container');
    const recsList = document.getElementById('recs-list');

    if (analyzerForm) {
        analyzerForm.addEventListener('submit', function (e) {
            e.preventDefault();
            
            const emailContent = emailInput.value.trim();
            if (!emailContent) return;
            
            // Set loading state
            analyzeBtn.disabled = True;
            analyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>ANALYZING CORE...';
            
            fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email_text: emailContent })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Prediction API failed.');
                }
                return response.json();
            })
            .then(data => {
                displayResults(data, emailContent);
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Analysis failed. Please confirm the server is running properly.');
            })
            .finally(() => {
                // Reset button state
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = '<i class="bi bi-shield-shaded me-2"></i>RUN INTEL ANALYSIS';
            });
        });
    }

    function displayResults(data, originalText) {
        // Hide placeholder and show results
        if (defaultPlaceholder) defaultPlaceholder.style.display = 'none';
        resultBox.style.display = 'block';
        textPreview.style.display = 'block';
        recsContainer.style.display = 'block';
        
        const prediction = data.prediction;
        const confidence = (data.confidence * 100).toFixed(1);
        
        // Reset classes
        resultBox.className = 'result-box';
        
        if (prediction === 1) {
            // Phishing
            resultBox.classList.add('result-phishing');
            resultText.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2"></i>PHISHING THREAT DETECTED`;
            confidenceText.textContent = `Confidence Level: ${confidence}% Risk Assessment`;
            confidenceBar.style.width = `${confidence}%`;
            confidenceBar.style.backgroundColor = '#f43f5e'; // Red
        } else {
            // Safe
            resultBox.classList.add('result-safe');
            resultText.innerHTML = `<i class="bi bi-shield-fill-check me-2"></i>SECURE EMAIL PROFILE`;
            confidenceText.textContent = `Confidence Level: ${confidence}% Legitimate Score`;
            confidenceBar.style.width = `${confidence}%`;
            confidenceBar.style.backgroundColor = '#10b981'; // Green
        }
        
        // Render highlighted email content
        let highlightedText = escapeHTML(originalText);
        
        // Sort indicators by length descending to avoid replacing sub-words incorrectly
        const indicators = data.indicators || [];
        indicators.sort((a, b) => b.length - a.length);
        
        indicators.forEach(phrase => {
            const escapedPhrase = escapeHTML(phrase);
            const regex = new RegExp(`(${escapeRegExp(escapedPhrase)})`, 'gi');
            highlightedText = highlightedText.replace(regex, `<span class="flagged-indicator" title="Social engineering indicator phrase detected">$1</span>`);
        });
        
        textPreview.innerHTML = highlightedText;
        
        // Render security recommendations
        recsList.innerHTML = '';
        const recommendations = data.recommendations || [];
        recommendations.forEach(rec => {
            const li = document.createElement('div');
            li.className = `rec-item ${prediction === 1 ? 'rec-danger' : ''}`;
            li.innerHTML = `
                <h6 class="text-white"><i class="bi bi-check-circle-fill me-2 text-${prediction === 1 ? 'danger' : 'info'}"></i>${escapeHTML(rec.title)}</h6>
                <p class="text-muted small mb-0">${escapeHTML(rec.description)}</p>
            `;
            recsList.appendChild(li);
        });
    }

    // Helper functions for safe rendering
    function escapeHTML(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
    }
});
