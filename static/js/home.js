document.addEventListener('DOMContentLoaded', function () {
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();

            const targetId = this.getAttribute('href');
            if (targetId === "#") return;

            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 80, // Adjust for fixed navbar
                    behavior: 'smooth'
                });
            }
        });
    });

    // Animate elements when scrolled into view
    const animateOnScroll = function () {
        const elements = document.querySelectorAll('.animate-on-scroll');

        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const windowHeight = window.innerHeight;

            if (elementPosition < windowHeight - 100) {
                element.classList.add('fade-in');
            }
        });
    };

    // Initial check for elements in view
    animateOnScroll();

    // Check on scroll
    window.addEventListener('scroll', animateOnScroll);

    // Feature card hover effects
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach(card => {
        card.addEventListener('mouseenter', function () {
            const icon = this.querySelector('.feature-icon i');
            icon.classList.add('fa-beat');
            setTimeout(() => {
                icon.classList.remove('fa-beat');
            }, 1000);
        });
    });

    // Timeline animation
    const timelineItems = document.querySelectorAll('.timeline-item');
    timelineItems.forEach((item, index) => {
        setTimeout(() => {
            item.classList.add('fade-in');
        }, 300 * index);
    });

    // Validation for newsletter form if exists
    const newsletterForm = document.getElementById('newsletter-form');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const emailInput = this.querySelector('input[type="email"]');
            const email = emailInput.value.trim();

            if (!isValidEmail(email)) {
                showFormMessage(this, 'Please enter a valid email address', 'danger');
                return;
            }

            // Here you would normally send the form data to your server
            // For demo purposes, we'll just show a success message
            showFormMessage(this, 'Thank you for subscribing!', 'success');
            emailInput.value = '';
        });
    }

    // Email validation helper function
    function isValidEmail(email) {
        const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(email);
    }

    // Form message helper function
    function showFormMessage(form, message, type) {
        let messageEl = form.querySelector('.form-message');

        if (!messageEl) {
            messageEl = document.createElement('div');
            messageEl.className = 'form-message mt-2';
            form.appendChild(messageEl);
        }

        messageEl.textContent = message;
        messageEl.className = `form-message mt-2 text-${type}`;

        setTimeout(() => {
            messageEl.textContent = '';
        }, 5000);
    }

    // Parallax effect for hero section
    const heroSection = document.querySelector('.hero');
    if (heroSection) {
        window.addEventListener('scroll', function () {
            const scrollPosition = window.scrollY;
            heroSection.style.backgroundPosition = `50% ${scrollPosition * 0.05}px`;
        });
    }

    // Counter animation for statistics if they exist
    const statsCounters = document.querySelectorAll('.stats-counter');
    if (statsCounters.length > 0) {
        const countUp = function (el) {
            const target = parseInt(el.getAttribute('data-target'), 10);
            const duration = 2000; // ms
            const step = target / (duration / 16); // 60fps
            let current = 0;

            const timer = setInterval(() => {
                current += step;
                el.textContent = Math.round(current);

                if (current >= target) {
                    el.textContent = target;
                    clearInterval(timer);
                }
            }, 16);
        };

        const observerOptions = {
            threshold: 0.5
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    countUp(entry.target);
                    observer.unobserve(entry.target);
                }
            });
        }, observerOptions);

        statsCounters.forEach(counter => {
            observer.observe(counter);
        });
    }
});