document.addEventListener('DOMContentLoaded', function () {
    // --- Password Visibility Toggle ---
    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password'); // Added confirm

    if (togglePassword && passwordInput) {
        togglePassword.addEventListener('click', function () {
            // Toggle the password field type
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            if (confirmPasswordInput) { // Toggle confirm field too if it exists
                confirmPasswordInput.setAttribute('type', type);
            }
            // Toggle the eye icon
            this.querySelector('i').classList.toggle('fa-eye');
            this.querySelector('i').classList.toggle('fa-eye-slash');
        });
    }

    // --- Registration Form Validation ---
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        const usernameInput = document.getElementById('username');
        const passwordFeedback = document.getElementById('password-feedback');
        const confirmPasswordFeedback = document.getElementById('confirm_password')?.nextElementSibling; // Get feedback div
        const passwordStrengthDiv = document.getElementById('password-strength'); // Optional strength indicator

        // Helper function for Bootstrap validation classes
        const setValidationState = (inputElement, isValid, feedbackElement, message = null) => {
            if (isValid) {
                inputElement.classList.remove('is-invalid');
                inputElement.classList.add('is-valid');
                if (feedbackElement) feedbackElement.textContent = ''; // Clear feedback
            } else {
                inputElement.classList.remove('is-valid');
                inputElement.classList.add('is-invalid');
                if (feedbackElement && message) feedbackElement.textContent = message;
            }
        };

        // 1. Username Validation (on input)
        if (usernameInput) {
            usernameInput.addEventListener('input', () => {
                const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
                const isValid = usernameRegex.test(usernameInput.value);
                setValidationState(usernameInput, isValid, usernameInput.nextElementSibling,
                    'Username must be 3-20 characters (letters, numbers, underscore only).');
            });
        }

        // 2. Password Strength Check (Optional - basic example)
        if (passwordInput && passwordStrengthDiv) {
            passwordInput.addEventListener('input', () => {
                const pass = passwordInput.value;
                let strength = 0;
                let feedback = '';
                let className = '';

                if (pass.length >= 8) strength++;
                if (pass.length >= 10) strength++;
                if (/[A-Z]/.test(pass)) strength++; // Uppercase
                if (/[a-z]/.test(pass)) strength++; // Lowercase
                if (/[0-9]/.test(pass)) strength++; // Numbers
                if (/[^A-Za-z0-9]/.test(pass)) strength++; // Symbols

                if (strength < 3) {
                    feedback = 'Weak'; className = 'text-danger';
                } else if (strength < 5) {
                    feedback = 'Medium'; className = 'text-warning';
                } else {
                    feedback = 'Strong'; className = 'text-success';
                }

                passwordStrengthDiv.textContent = `Strength: ${feedback}`;
                passwordStrengthDiv.className = `mt-1 small ${className}`;

                // Also validate length requirement
                const isLengthValid = pass.length >= 8;
                setValidationState(passwordInput, isLengthValid, passwordFeedback,
                    isLengthValid ? '' : 'Password must be at least 8 characters long.');

                // Trigger confirm password validation when password changes
                if (confirmPasswordInput) {
                    validateConfirmPassword();
                }
            });
        }

        // 3. Confirm Password Validation (on input)
        const validateConfirmPassword = () => {
            if (passwordInput && confirmPasswordInput) {
                const pass = passwordInput.value;
                const confirmPass = confirmPasswordInput.value;
                const isValid = pass.length >= 8 && confirmPass.length >= 8 && pass === confirmPass;
                setValidationState(confirmPasswordInput, isValid, confirmPasswordFeedback,
                    pass !== confirmPass ? 'Passwords do not match.' : 'Password must be at least 8 characters.');
            }
        };

        if (confirmPasswordInput) {
            confirmPasswordInput.addEventListener('input', validateConfirmPassword);
        }


        // 4. Form Submission Validation (using Bootstrap's built-in)
        registerForm.addEventListener('submit', function (event) {
            // Check username validity again on submit
            if (usernameInput) {
                const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
                if (!usernameRegex.test(usernameInput.value)) {
                    setValidationState(usernameInput, false, usernameInput.nextElementSibling,
                        'Username must be 3-20 characters (letters, numbers, underscore only).');
                    event.preventDefault();
                    event.stopPropagation();
                } else {
                    setValidationState(usernameInput, true, usernameInput.nextElementSibling);
                }
            }
            // Check password length again on submit
            if (passwordInput) {
                if (passwordInput.value.length < 8) {
                    setValidationState(passwordInput, false, passwordFeedback, 'Password must be at least 8 characters long.');
                    event.preventDefault();
                    event.stopPropagation();
                } else {
                    setValidationState(passwordInput, true, passwordFeedback);
                }
            }
            // Check confirm password match again on submit
            if (confirmPasswordInput) {
                validateConfirmPassword(); // Run the validation logic
                if (!confirmPasswordInput.classList.contains('is-valid')) { // Check if it's valid
                    event.preventDefault();
                    event.stopPropagation();
                }
            }


            // Bootstrap's checkValidity handles required fields, email format, etc.
            if (!registerForm.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }

            registerForm.classList.add('was-validated'); // Show Bootstrap feedback styles
        }, false);
    }

});