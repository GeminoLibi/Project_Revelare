// Professional Features Authentication Check
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

async function checkProAuth() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            credentials: 'include'
        });

        if (!response.ok) {
            window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
            return;
        }

        const userData = await response.json();
        
        // Check if user has professional access
        if (userData.accessTier === 'hobbyist') {
            showUpgradeModal(userData.accessTier);
            return;
        }

        // User has professional or enterprise access
        return userData;
    } catch (error) {
        console.error('Pro auth check failed:', error);
        window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
    }
}

function showUpgradeModal(currentTier) {
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
                    <button onclick="window.location.href='/user-dashboard.html'" class="block w-full bg-gray-600 hover:bg-gray-700 text-white font-medium py-3 px-4 rounded-lg transition">
                        <i class="fas fa-arrow-left mr-2"></i>Return to Dashboard
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

// Run auth check when page loads
document.addEventListener('DOMContentLoaded', checkProAuth);

