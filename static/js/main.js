// Main JavaScript for BlockInspect

document.addEventListener('DOMContentLoaded', function () {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-dismiss alerts
    setTimeout(function () {
        var alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function (alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;

            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 70,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Project search functionality (on projects page)
    const projectSearch = document.getElementById('project-search');
    if (projectSearch) {
        projectSearch.addEventListener('keyup', function () {
            const searchTerm = projectSearch.value.toLowerCase();
            const projectRows = document.querySelectorAll('tbody tr');

            projectRows.forEach(row => {
                const projectName = row.querySelector('td:first-child').textContent.toLowerCase();
                const location = row.querySelector('td:nth-child(2)').textContent.toLowerCase();

                if (projectName.includes(searchTerm) || location.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }

    // Function to verify blockchain hash (placeholder)
    window.verifyBlockchainRecord = function (txHash) {
        // In a real implementation, this would query a blockchain explorer or node
        // For demo purposes, we just show a confirmation
        alert('Connecting to blockchain network to verify transaction: ' + txHash);

        // Simulate verification delay
        setTimeout(function () {
            alert('Transaction verified successfully on the blockchain!');
        }, 1500);
    };

    // Initialize blockchain connection if Web3 is available
    if (typeof web3 !== 'undefined') {
        initBlockchainConnection();
    }
});

// Initialize blockchain connection
function initBlockchainConnection() {
    // This is a placeholder for real blockchain integration
    console.log('Web3 detected, initializing blockchain connection...');

    // In a real implementation, this would connect to a blockchain network
    // For example Ethereum, using MetaMask or other providers
    try {
        window.web3 = new Web3(window.ethereum);
        console.log('Blockchain connection initialized');
    } catch (error) {
        console.error('Error initializing blockchain connection:', error);
    }
}

// Function to format dates
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

// Function to create a new inspection
function submitInspection(projectId) {
    // Get form data
    const notes = document.getElementById('inspection-notes').value;
    const structural = document.getElementById('structural-status').value;
    const electrical = document.getElementById('electrical-status').value;
    const plumbing = document.getElementById('plumbing-status').value;
    const safety = document.getElementById('safety-status').value;

    // Validate form
    if (!notes) {
        alert('Please enter inspection notes');
        return false;
    }

    // Show loading indicator
    document.getElementById('submit-btn').innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
    document.getElementById('submit-btn').disabled = true;

    // In a real app, this would use fetch/AJAX to submit the form
    // For demo, we'll simulate blockchain processing
    setTimeout(function () {
        // Simulate blockchain submission
        const txHash = '0x' + Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('');

        document.getElementById('blockchain-status').innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>
                Inspection recorded on blockchain with transaction hash:
                <br>
                <code>${txHash}</code>
            </div>
        `;

        document.getElementById('submit-btn').innerHTML = 'Submit Inspection';
        document.getElementById('submit-btn').disabled = false;
    }, 2000);

    return false;
}