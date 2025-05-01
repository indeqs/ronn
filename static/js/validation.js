document.addEventListener('DOMContentLoaded', function () {
    // --- Password Visibility Toggle ---
    // Toggle visibility for the main password field
    const togglePasswordButton = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');

    if (togglePasswordButton && passwordInput) {
        togglePasswordButton.addEventListener('click', function () {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);

            // Toggle the eye icon
            const icon = this.querySelector('i');
            if (icon) {
                icon.classList.toggle('fa-eye');
                icon.classList.toggle('fa-eye-slash');
            }
        });
    }

    // Toggle visibility for the confirm password field
    const toggleConfirmPasswordButton = document.getElementById('toggleConfirmPassword');
    const confirmPasswordInput = document.getElementById('confirm_password');

    if (toggleConfirmPasswordButton && confirmPasswordInput) {
        toggleConfirmPasswordButton.addEventListener('click', function () {
            const type = confirmPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            confirmPasswordInput.setAttribute('type', type);

            // Toggle the eye icon
            const icon = this.querySelector('i');
            if (icon) {
                icon.classList.toggle('fa-eye');
                icon.classList.toggle('fa-eye-slash');
            }
        });
    }

    // --- Registration Form Validation ---
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        const usernameInput = document.getElementById('username');
        const passwordFeedback = document.getElementById('password-feedback');
        // Use optional chaining in case confirm_password is not present for some reason
        const confirmPasswordFeedback = document.getElementById('confirm_password')?.nextElementSibling;
        const passwordStrengthDiv = document.getElementById('password-strength'); // Optional strength indicator

        // Helper function for Bootstrap validation classes
        const setValidationState = (inputElement, isValid, feedbackElement, message = null) => {
            if (inputElement) { // Added a check to ensure the element exists
                if (isValid) {
                    inputElement.classList.remove('is-invalid');
                    inputElement.classList.add('is-valid');
                    if (feedbackElement) feedbackElement.textContent = ''; // Clear feedback
                } else {
                    inputElement.classList.remove('is-valid');
                    inputElement.classList.add('is-invalid');
                    if (feedbackElement && message) feedbackElement.textContent = message;
                }
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

                // Also validate length requirement using setValidationState
                const isLengthValid = pass.length >= 8;
                // Pass the passwordFeedback element to setValidationState
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
            let formIsValid = true; // Flag to track overall form validity

            // Check username validity
            if (usernameInput) {
                const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
                if (!usernameRegex.test(usernameInput.value)) {
                    setValidationState(usernameInput, false, usernameInput.nextElementSibling,
                        'Username must be 3-20 characters (letters, numbers, underscore only).');
                    formIsValid = false;
                } else {
                    setValidationState(usernameInput, true, usernameInput.nextElementSibling);
                }
            }

            // Check password length
            if (passwordInput) {
                if (passwordInput.value.length < 8) {
                    setValidationState(passwordInput, false, passwordFeedback, 'Password must be at least 8 characters long.');
                    formIsValid = false;
                } else {
                    setValidationState(passwordInput, true, passwordFeedback);
                }
            }

            // Check confirm password match and length
            if (confirmPasswordInput) {
                validateConfirmPassword(); // Run the validation logic
                if (!confirmPasswordInput.classList.contains('is-valid')) { // Check if it's valid
                    formIsValid = false;
                }
            }

            // Bootstrap's checkValidity handles required fields, email format, etc.
            // We still run this to get feedback on other fields (email, role)
            if (!registerForm.checkValidity()) {
                formIsValid = false;
            }

            // Prevent form submission if any custom validation failed
            if (!formIsValid) {
                event.preventDefault();
                event.stopPropagation();
            }

            registerForm.classList.add('was-validated'); // Show Bootstrap feedback styles
        }, false);
    }

});
