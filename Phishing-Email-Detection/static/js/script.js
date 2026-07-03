document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const scanBtn = document.getElementById('scan-btn');
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const scanOverlay = document.getElementById('scan-overlay');
    const scanStatusText = document.getElementById('scan-status-text');
    
    const subjectInput = document.getElementById('subject');
    const bodyInput = document.getElementById('body');
    const senderInput = document.getElementById('sender');
    const urlInput = document.getElementById('url');

    // 1. Example Emails Trigger Pre-fill
    const exampleCards = document.querySelectorAll('.example-card');
    exampleCards.forEach(card => {
        card.addEventListener('click', () => {
            const id = card.getAttribute('data-id');
            // Fetch example email from backend
            fetch(`/example/${id}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert(data.error);
                        return;
                    }
                    subjectInput.value = data.subject || '';
                    bodyInput.value = data.body || '';
                    senderInput.value = data.sender || '';
                    urlInput.value = data.url || '';
                    
                    // Smooth scroll to the form
                    document.getElementById('scan-hub').scrollIntoView({ behavior: 'smooth' });
                    
                    // Flash the inputs to show they were updated
                    [subjectInput, bodyInput, senderInput, urlInput].forEach(el => {
                        el.style.borderColor = 'var(--primary)';
                        setTimeout(() => {
                            el.style.borderColor = 'var(--border-color)';
                        }, 800);
                    });
                })
                .catch(err => {
                    console.error("Error fetching template: ", err);
                });
        });
    });

    // 2. Drag & Drop File Upload Handler
    uploadZone.addEventListener('click', () => fileInput.click());

    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    ['dragleave', 'dragend'].forEach(type => {
        uploadZone.addEventListener(type, () => {
            uploadZone.classList.remove('dragover');
        });
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // Parse email file (.txt)
    function handleFileUpload(file) {
        if (!file.name.endsWith('.txt')) {
            alert("Only raw email text (.txt) files are supported.");
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            parseEmailFileContent(content);
        };
        reader.readAsText(file);
    }

    function parseEmailFileContent(text) {
        const lines = text.split('\n');
        let subject = '';
        let sender = '';
        let url = '';
        let bodyLines = [];
        let inHeaders = true;

        for (let i = 0; i < lines.length; i++) {
            let line = lines[i].trim();
            if (inHeaders) {
                if (line === '') {
                    inHeaders = false;
                    continue;
                }
                const lowerLine = line.toLowerCase();
                if (lowerLine.startsWith('subject:')) {
                    subject = line.substring(8).trim();
                } else if (lowerLine.startsWith('from:')) {
                    const fromVal = line.substring(5).trim();
                    // Match email address inside angle brackets or match plain email
                    const emailRegex = /<([^>]+)>/;
                    const plainEmailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/;
                    const match = fromVal.match(emailRegex) || fromVal.match(plainEmailRegex);
                    sender = match ? match[1] : fromVal;
                } else if (lowerLine.startsWith('url:') || lowerLine.startsWith('link:')) {
                    url = line.substring(4).trim();
                }
            } else {
                bodyLines.push(lines[i]);
            }
        }

        const body = bodyLines.join('\n').trim();

        // If it was just a plain text file without standard headers, dump all in body
        if (!subject && !sender && bodyLines.length === 0) {
            bodyInput.value = text;
            subjectInput.value = "Imported File Content";
            senderInput.value = "";
            urlInput.value = "";
        } else {
            subjectInput.value = subject;
            senderInput.value = sender;
            urlInput.value = url;
            bodyInput.value = body;
        }

        // Inform user of successful load
        const uploadMsg = uploadZone.querySelector('.upload-message');
        const originalText = uploadMsg.innerHTML;
        uploadMsg.innerHTML = `<span style="color: var(--safe);"><i class="fas fa-check-circle"></i> File loaded and parsed successfully!</span>`;
        setTimeout(() => {
            uploadMsg.innerHTML = originalText;
        }, 3000);
    }

    // 3. Multi-stage Scan Animation & Form Validation
    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            e.preventDefault();

            // Validate fields
            const subject = subjectInput.value.trim();
            const body = bodyInput.value.trim();
            const sender = senderInput.value.trim();

            if (!subject && !body && !sender) {
                alert("Please fill out at least one field (Sender, Subject, or Body) to perform analysis.");
                return;
            }

            // Launch Scanner Overlay
            scanOverlay.classList.add('active');
            
            const stages = [
                { text: "Initializing Core Threat Scanner...", delay: 0 },
                { text: "Extracting NLP Token Frequencies...", delay: 400 },
                { text: "Invoking Multinomial Naive Bayes Model...", delay: 800 },
                { text: "Scanning URLs against Suspicious TLD Lists...", delay: 1200 },
                { text: "Analyzing Sender Domain Signatures...", delay: 1600 },
                { text: "Compiling Heuristics and Recommendations...", delay: 2000 },
                { text: "Done! Rendering Cyber threat report...", delay: 2400 }
            ];

            stages.forEach(stage => {
                setTimeout(() => {
                    scanStatusText.textContent = stage.text;
                }, stage.delay);
            });

            // Submit form to backend after last animation stage finishes
            setTimeout(() => {
                scanForm.submit();
            }, 2700);
        });
    }
});
