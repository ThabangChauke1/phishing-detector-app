// Main JavaScript for the Email Phishing Detector

document.addEventListener('DOMContentLoaded', function() {
    // File upload preview
    const fileInput = document.getElementById('email_file');
    const emailTextarea = document.getElementById('email_text');
    
    if(fileInput && emailTextarea) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if(!file) return;
            
            // Show file name in the interface
            const fileNameDisplay = document.createElement('div');
            fileNameDisplay.classList.add('mt-2', 'text-sm', 'text-gray-600');
            fileNameDisplay.textContent = `Selected file: ${file.name}`;
            
            // Add the file name display after the file input
            fileInput.parentNode.parentNode.appendChild(fileNameDisplay);
            
            // If it's a text file, read and display in the textarea
            if(file.type === 'text/plain') {
                const reader = new FileReader();
                reader.onload = function(e) {
                    emailTextarea.value = e.target.result;
                };
                reader.readAsText(file);
            }
        });
    }
    
    // Character counter for textarea
    if(emailTextarea) {
        const maxLength = 50000;
        
        // Create counter element
        const counter = document.createElement('div');
        counter.classList.add('text-xs', 'text-gray-500', 'text-right', 'mt-1');
        emailTextarea.parentNode.appendChild(counter);
        
        // Update counter
        function updateCounter() {
            const remaining = maxLength - emailTextarea.value.length;
            counter.textContent = `${emailTextarea.value.length} / ${maxLength} characters`;
            
            if(remaining < 1000) {
                counter.classList.add('text-red-500');
                counter.classList.remove('text-gray-500');
            } else {
                counter.classList.add('text-gray-500');
                counter.classList.remove('text-red-500');
            }
        }
        
        // Initial update and event listener
        updateCounter();
        emailTextarea.addEventListener('input', function() {
            updateCounter();
            if(emailTextarea.value.length > maxLength) {
                emailTextarea.value = emailTextarea.value.substring(0, maxLength);
            }
        });
    }
    
    // Handle form submission with loading state
    const form = document.querySelector('form');
    if(form) {
        form.addEventListener('submit', function() {
            // Create and show loading overlay
            const loadingOverlay = document.createElement('div');
            loadingOverlay.classList.add('fixed', 'inset-0', 'bg-black', 'bg-opacity-50', 'flex', 'items-center', 'justify-center', 'z-50');
            loadingOverlay.innerHTML = `
                <div class="bg-white p-8 rounded-lg shadow-lg text-center">
                    <div class="lds-ring"><div></div><div></div><div></div><div></div></div>
                    <p class="mt-4 text-gray-700 font-medium">Analyzing email...</p>
                </div>
            `;
            document.body.appendChild(loadingOverlay);
        });
    }
    
    // Tooltips for risk indicators (on results page)
    const riskIndicators = document.querySelectorAll('.risk-indicator');
    if(riskIndicators.length > 0) {
        riskIndicators.forEach(indicator => {
            indicator.addEventListener('mouseenter', function() {
                const tooltip = this.querySelector('.tooltip');
                if(tooltip) {
                    tooltip.classList.remove('hidden');
                }
            });
            
            indicator.addEventListener('mouseleave', function() {
                const tooltip = this.querySelector('.tooltip');
                if(tooltip) {
                    tooltip.classList.add('hidden');
                }
            });
        });
    }
    
    // Expand/collapse email content
    const emailContent = document.querySelector('.email-content');
    if(emailContent) {
        // Add expand/collapse button if content is long
        if(emailContent.scrollHeight > 400) {
            const expandButton = document.createElement('button');
            expandButton.classList.add('mt-2', 'text-blue-600', 'hover:text-blue-800', 'focus:outline-none', 'text-sm');
            expandButton.textContent = 'Show more';
            
            emailContent.parentNode.appendChild(expandButton);
            
            let expanded = false;
            expandButton.addEventListener('click', function() {
                if(expanded) {
                    emailContent.classList.add('max-h-96');
                    expandButton.textContent = 'Show more';
                } else {
                    emailContent.classList.remove('max-h-96');
                    expandButton.textContent = 'Show less';
                }
                expanded = !expanded;
            });
        }
    }
    
    // Add copy button for API usage
    const apiSection = document.getElementById('api-usage');
    if(apiSection) {
        const codeBlock = apiSection.querySelector('code');
        if(codeBlock) {
            const copyButton = document.createElement('button');
            copyButton.classList.add('absolute', 'top-2', 'right-2', 'bg-gray-200', 'hover:bg-gray-300', 'rounded', 'p-1');
            copyButton.innerHTML = '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"></path><path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"></path></svg>';
            
            copyButton.addEventListener('click', function() {
                navigator.clipboard.writeText(codeBlock.textContent).then(() => {
                    copyButton.innerHTML = '<svg class="w-5 h-5 text-green-600" fill="currentColor" viewBox="0 0 20 20"><path d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"></path></svg>';
                    setTimeout(() => {
                        copyButton.innerHTML = '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"></path><path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"></path></svg>';
                    }, 2000);
                });
            });
            
            // Add button to the code block container
            codeBlock.parentNode.style.position = 'relative';
            codeBlock.parentNode.appendChild(copyButton);
        }
    }
    
    // Add loading spinner CSS
    const style = document.createElement('style');
    style.textContent = `
        .lds-ring {
            display: inline-block;
            position: relative;
            width: 80px;
            height: 80px;
        }
        .lds-ring div {
            box-sizing: border-box;
            display: block;
            position: absolute;
            width: 64px;
            height: 64px;
            margin: 8px;
            border: 8px solid #3b82f6;
            border-radius: 50%;
            animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
            border-color: #3b82f6 transparent transparent transparent;
        }
        .lds-ring div:nth-child(1) {
            animation-delay: -0.45s;
        }
        .lds-ring div:nth-child(2) {
            animation-delay: -0.3s;
        }
        .lds-ring div:nth-child(3) {
            animation-delay: -0.15s;
        }
        @keyframes lds-ring {
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(360deg);
            }
        }
    `;
    document.head.appendChild(style);
});