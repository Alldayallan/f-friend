document.addEventListener('DOMContentLoaded', function() {
    // Password strength validation
    const passwordField = document.querySelector('input[type="password"]');
    if (passwordField) {
        passwordField.addEventListener('input', function() {
            const password = this.value;
            const minLength = 8;
            const hasNumber = /\d/.test(password);
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            
            let isValid = password.length >= minLength && hasNumber && hasUpper && hasLower;
            
            if (password.length > 0) {
                if (!isValid) {
                    this.setCustomValidity('Password must be at least 8 characters long and contain numbers, uppercase and lowercase letters.');
                } else {
                    this.setCustomValidity('');
                }
            }
        });
    }

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
});
