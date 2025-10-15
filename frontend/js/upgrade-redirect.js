// Upgrade Redirect Script - Shared across professional feature pages
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

async function checkUserTierAndRedirect() {
    // Wait longer for navigation and authentication to complete first
    await new Promise(resolve => setTimeout(resolve, 2000));

    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            credentials: 'include' // This ensures cookies are sent
        });

        if (!response.ok) {
            console.log('Auth check failed, status:', response.status);
            // Don't redirect to login immediately - let the main auth check handle it
            console.log('Authentication check failed in upgrade-redirect.js, but not redirecting to avoid conflicts');
            return;
        }

        const userData = await response.json();

        // Check if user has access to professional features
        // Note: Case management is now allowed for hobbyists with limits
        if (userData.accessTier === 'hobbyist') {
            // Only show upgrade modal for non-case-management pages
            const currentPage = window.location.pathname;
            const caseManagementPages = ['/pro/create_case.html', '/pro/case-dashboard.html'];

            if (!caseManagementPages.includes(currentPage)) {
                showUpgradeModal(userData.accessTier);
            }
        }
    } catch (error) {
        console.error('Auth check failed in upgrade-redirect.js:', error);
        // Don't redirect to login - let the main auth system handle it
        console.log('Not redirecting to login from upgrade-redirect.js to avoid conflicts');
    }
}

function showUpgradeModal(currentTier) {
    // Create upgrade modal
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-gray-800 p-8 rounded-lg max-w-md w-full mx-4 border border-gray-600">
            <div class="text-center">
                <i class="fas fa-lock text-yellow-500 text-4xl mb-4"></i>
                <h2 class="text-2xl font-bold text-white mb-4">Professional Feature</h2>
                <p class="text-gray-300 mb-6">
                    This feature is available with Professional or Enterprise subscriptions. 
                    Upgrade now to access advanced tools and capabilities.
                </p>
                <div class="space-y-3">
                    <a href="/subscription.html" class="block w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition text-center">
                        <i class="fas fa-star mr-2"></i>Upgrade to Professional
                    </a>
                    <button onclick="this.closest('.fixed').remove()" class="block w-full bg-gray-600 hover:bg-gray-700 text-white font-medium py-3 px-4 rounded-lg transition">
                        <i class="fas fa-arrow-left mr-2"></i>Return to Dashboard
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Add click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// Run check when page loads
document.addEventListener('DOMContentLoaded', function() {
    checkUserTierAndRedirect();
});
