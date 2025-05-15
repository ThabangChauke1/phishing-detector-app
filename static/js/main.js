// Add any client-side interactions here
document.addEventListener('DOMContentLoaded', function() {
    // Example: Add a character counter for the textarea
    const textarea = document.getElementById('email_text');
    if (textarea) {
        textarea.addEventListener('input', function() {
            const count = textarea.value.length;
            if (count > 5000) {
                textarea.value = textarea.value.substring(0, 5000);
            }
        });
    }
});