// General Authentication Script - Ensures user is logged in for protected pages
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

async function checkAuthentication() {
    // Wait longer for navigation to load and authenticate first
    await new Promise(resolve => setTimeout(resolve, 1500));

    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            credentials: 'include' // This ensures cookies are sent
        });

        if (!response.ok) {
            console.log('Auth check failed, status:', response.status);
            window.location.href = '/login.html';
            return;
        }

        const userData = await response.json();
        console.log('Authentication confirmed for:', userData.firstName, userData.lastName, 'Tier:', userData.accessTier);

    } catch (error) {
        console.error('Auth check failed:', error);
        window.location.href = '/login.html';
    }
}

// Run check when page loads - with higher priority
document.addEventListener('DOMContentLoaded', function() {
    // Run auth check after a short delay to allow navigation to initialize
    setTimeout(checkAuthentication, 100);
});
