// Main JavaScript for the Email Phishing Detector

document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements upfront
    const form = document.querySelector('form');
    const fileInput = document.getElementById('email_file');
    const emailTextarea = document.getElementById('email_text');
    const submitButton = document.querySelector('button[type="submit"]');
    
    // File upload handling
    if(fileInput && emailTextarea) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if(!file) return;
            
            // File size validation - 5MB limit
            const maxSize = 5 * 1024 * 1024; // 5MB in bytes
            if(file.size > maxSize) {
                // Create error message for file size
                const sizeErrorMsg = document.createElement('div');
                sizeErrorMsg.classList.add('mt-2', 'text-red-600', 'text-sm');
                sizeErrorMsg.textContent = 'File is too large. Maximum size is 5MB.';
                
                // Remove any existing error message
                const existingError = fileInput.parentNode.parentNode.querySelector('.text-red-600');
                if(existingError) {
                    existingError.remove();
                }
                
                fileInput.parentNode.parentNode.appendChild(sizeErrorMsg);
                fileInput.value = ''; // Clear the file input
                return;
            }
            
            // Validate file type
            const validTypes = ['text/plain', 'message/rfc822'];
            const isValidExtension = file.name.endsWith('.eml') || file.name.endsWith('.txt');
            
            if(!validTypes.includes(file.type) && !isValidExtension) {
                // Create error message for file type
                const typeErrorMsg = document.createElement('div');
                typeErrorMsg.classList.add('mt-2', 'text-red-600', 'text-sm');
                typeErrorMsg.textContent = 'Invalid file type. Please upload a .txt or .eml file.';
                
                // Remove any existing error message
                const existingError = fileInput.parentNode.parentNode.querySelector('.text-red-600');
                if(existingError) {
                    existingError.remove();
                }
                
                fileInput.parentNode.parentNode.appendChild(typeErrorMsg);
                fileInput.value = ''; // Clear the file input
                return;
            }
            
            // Show file name in the interface
            const fileNameDisplay = document.createElement('div');
            fileNameDisplay.classList.add('mt-2', 'text-sm', 'text-gray-600');
            fileNameDisplay.textContent = `Selected file: ${file.name}`;
            
            // Remove any existing file name display
            const existingDisplay = fileInput.parentNode.parentNode.querySelector('.text-sm.text-gray-600');
            if(existingDisplay) {
                existingDisplay.remove();
            }
            
            // Add the file name display after the file input
            fileInput.parentNode.parentNode.appendChild(fileNameDisplay);
            
            // If it's a text file, read and display in the textarea
            if(file.type === 'text/plain' || file.name.endsWith('.eml') || file.name.endsWith('.txt')) {
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    emailTextarea.value = e.target.result;
                };
                
                reader.onerror = function() {
                    // Create error message for file reading error
                    const readErrorMsg = document.createElement('div');
                    readErrorMsg.classList.add('mt-2', 'text-red-600', 'text-sm');
                    readErrorMsg.textContent = 'Error reading file. Please try again or paste content directly.';
                    
                    // Remove any existing error message
                    const existingError = fileInput.parentNode.parentNode.querySelector('.text-red-600');
                    if(existingError) {
                        existingError.remove();
                    }
                    
                    fileInput.parentNode.parentNode.appendChild(readErrorMsg);
                };
                
                reader.readAsText(file);
            }
        });
    }
    
    // Character counter for textarea with improved validation feedback
    if(emailTextarea) {
        const maxLength = 50000;
        
        // Create counter element
        const counter = document.createElement('div');
        counter.classList.add('text-xs', 'text-gray-500', 'text-right', 'mt-1');
        emailTextarea.parentNode.appendChild(counter);
        
        // Update counter with validation feedback
        function updateCounter() {
            const remaining = maxLength - emailTextarea.value.length;
            
            if(emailTextarea.value.length === 0) {
                counter.textContent = 'Enter email content or upload a file';
                counter.classList.add('text-blue-500');
                counter.classList.remove('text-gray-500', 'text-red-500');
            } else if(remaining < 1000) {
                counter.textContent = `${emailTextarea.value.length} / ${maxLength} characters (${remaining} remaining)`;
                counter.classList.add('text-red-500');
                counter.classList.remove('text-gray-500', 'text-blue-500');
            } else {
                counter.textContent = `${emailTextarea.value.length} / ${maxLength} characters`;
                counter.classList.add('text-gray-500');
                counter.classList.remove('text-red-500', 'text-blue-500');
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
    
    // Handle form submission with COMBINED validation and loading state
    if(form) {
        form.addEventListener('submit', function(e) {
            // Validation: Check if both textarea is empty and no file is selected
            if(emailTextarea && emailTextarea.value.trim() === '' && 
               (!fileInput || !fileInput.files || fileInput.files.length === 0)) {
                
                e.preventDefault(); // Prevent form submission
                
                // Show error message
                const errorDiv = document.createElement('div');
                errorDiv.classList.add('bg-red-100', 'border', 'border-red-400', 'text-red-700', 'px-4', 'py-3', 'rounded', 'relative', 'mb-4');
                errorDiv.innerHTML = '<span class="block sm:inline">Please provide email content or upload a file for analysis.</span>';
                
                // Remove any existing error message
                const existingError = form.querySelector('.bg-red-100');
                if(existingError) {
                    existingError.remove();
                }
                
                // Add error at the top of the form
                form.insertBefore(errorDiv, form.firstChild);
                
                // Remove error after 5 seconds
                setTimeout(() => {
                    if(errorDiv.parentNode) {
                        errorDiv.remove();
                    }
                }, 5000);
                
                return false;
            }
            
            // If validation passes, show loading overlay
            const loadingOverlay = document.createElement('div');
            loadingOverlay.classList.add('fixed', 'inset-0', 'bg-black', 'bg-opacity-50', 'flex', 'items-center', 'justify-center', 'z-50');
            loadingOverlay.innerHTML = `
                <div class="bg-white p-8 rounded-lg shadow-lg text-center">
                    <div class="spinner mx-auto"></div>
                    <p class="mt-4 text-gray-700 font-medium">Analyzing email...</p>
                </div>
            `;
            document.body.appendChild(loadingOverlay);
        });
    }
    
    // The rest of your code remains unchanged...
    // Generate tooltips for highlighted elements
    const highlightedElements = document.querySelectorAll('.suspicious-highlight, .suspicious-url-highlight, .url-highlight, .email-highlight, .suspicious-email-highlight, .urgent-highlight, .financial-highlight');
    
    if(highlightedElements.length > 0) {
        highlightedElements.forEach(element => {
            // Create tooltip if it has a description
            const description = element.getAttribute('data-description');
            if(description) {
                const tooltip = document.createElement('div');
                tooltip.classList.add('highlight-tooltip');
                tooltip.textContent = description;
                element.appendChild(tooltip);
            }
        });
    }
    
    
    // Create highlight legend if there are highlights
    if(highlightedElements.length > 0) {
        const emailContent = document.querySelector('.email-content');
        if(emailContent) {
            const legend = document.createElement('div');
            legend.classList.add('highlight-legend');
            
            // Define legend items based on what's in the email
            const legendItems = [
                { class: 'suspicious-highlight', color: 'legend-suspicious', label: 'Suspicious Phrase' },
                { class: 'url-highlight', color: 'legend-url', label: 'URL' },
                { class: 'suspicious-url-highlight', color: 'legend-suspicious-url', label: 'Suspicious URL' },
                { class: 'email-highlight', color: 'legend-email', label: 'Email Address' },
                { class: 'urgent-highlight', color: 'legend-urgent', label: 'Urgent Language' },
                { class: 'financial-highlight', color: 'legend-financial', label: 'Financial Term' }
            ];
            
            // Only add legend items that exist in the email
            legendItems.forEach(item => {
                if(document.querySelector(`.${item.class}`)) {
                    const legendItem = document.createElement('div');
                    legendItem.classList.add('legend-item');
                    legendItem.innerHTML = `
                        <div class="legend-color ${item.color}"></div>
                        <div>${item.label}</div>
                    `;
                    legend.appendChild(legendItem);
                }
            });
            
            // Insert legend before email content
            emailContent.parentNode.insertBefore(legend, emailContent);
        }
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
    
    // Copy results to clipboard button
    const resultContainer = document.querySelector('.result-container');
    if(resultContainer) {
        const copyButton = document.createElement('button');
        copyButton.classList.add('mt-4', 'bg-gray-100', 'hover:bg-gray-200', 'text-gray-800', 'font-bold', 'py-2', 'px-4', 'rounded', 'inline-flex', 'items-center');
        copyButton.innerHTML = `
            <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"></path>
                <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"></path>
            </svg>
            <span>Copy Results</span>
        `;
        
        copyButton.addEventListener('click', function() {
            // Create a text summary of the results
            const prediction = document.querySelector('h2').textContent;
            const probability = document.querySelector('.result-summary .text-xl').textContent;
            
            let indicators = '';
            document.querySelectorAll('.risk-indicator h4').forEach(indicator => {
                indicators += `- ${indicator.textContent}\n`;
            });
            
            // Include highlighted elements in the summary
            let highlightedSummary = '';
            const highlightCategories = {
                '.suspicious-url-highlight': 'Suspicious URLs',
                '.url-highlight': 'URLs',
                '.suspicious-highlight': 'Suspicious Phrases',
                '.urgent-highlight': 'Urgent Language',
                '.financial-highlight': 'Financial Terms'
            };
            
            for(const [selector, title] of Object.entries(highlightCategories)) {
                const elements = document.querySelectorAll(selector);
                if(elements.length > 0) {
                    highlightedSummary += `\n${title}:\n`;
                    elements.forEach(el => {
                        highlightedSummary += `- ${el.textContent.trim()}\n`;
                    });
                }
            }
            
            const resultText = `
Email Phishing Analysis Results:
===============================
Verdict: ${prediction}
Confidence: ${probability}

Risk Indicators:
${indicators}
${highlightedSummary}

Analyzed by Email Phishing Detector
            `.trim();
            
            // Copy to clipboard
            navigator.clipboard.writeText(resultText).then(() => {
                copyButton.innerHTML = `
                    <svg class="w-4 h-4 mr-2 text-green-600" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"></path>
                    </svg>
                    <span>Copied!</span>
                `;
                setTimeout(() => {
                    copyButton.innerHTML = `
                        <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"></path>
                            <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"></path>
                        </svg>
                        <span>Copy Results</span>
                    `;
                }, 2000);
            });
        });
        
        // Add the button to the result container
        const buttonContainer = document.querySelector('.action-buttons');
        if(buttonContainer) {
            buttonContainer.appendChild(copyButton);
        } else {
            const container = document.createElement('div');
            container.classList.add('flex', 'justify-center', 'mt-4');
            container.appendChild(copyButton);
            resultContainer.appendChild(container);
        }
    }
    
    // Feature explanation toggling
    const featureButtons = document.querySelectorAll('.feature-explanation-toggle');
    if(featureButtons.length > 0) {
        featureButtons.forEach(button => {
            button.addEventListener('click', function() {
                const explanation = this.nextElementSibling;
                explanation.classList.toggle('hidden');
                
                // Update toggle text
                if(explanation.classList.contains('hidden')) {
                    this.textContent = 'Show explanation';
                } else {
                    this.textContent = 'Hide explanation';
                }
            });
        });
    }
});