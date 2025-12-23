/**
 * AI Assistant Component for Project Revelare
 * Provides intelligent analysis assistance using OpenAI or Anthropic APIs
 */
class AIAssistant {
    constructor(options = {}) {
        this.apiEndpoint = options.apiEndpoint || '/api/ai_assistant';
        this.projectName = options.projectName || '';
        this.containerId = options.containerId || 'ai-assistant-container';
        this.isOpen = false;
        this.conversationHistory = [];
        this.init();
    }

    init() {
        this.createUI();
        this.attachEventListeners();
    }

    createUI() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        container.innerHTML = `
            <div id="ai-assistant-toggle" class="ai-assistant-toggle">
                <i class="fas fa-robot"></i>
                <span>AI Assistant</span>
            </div>
            <div id="ai-assistant-panel" class="ai-assistant-panel" style="display: none;">
                <div class="ai-assistant-header">
                    <h3><i class="fas fa-robot"></i> AI Analysis Assistant</h3>
                    <button id="ai-assistant-close" class="ai-assistant-close">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div id="ai-assistant-messages" class="ai-assistant-messages"></div>
                <div class="ai-assistant-input-container">
                    <div class="ai-assistant-suggestions">
                        <button class="suggestion-btn" data-query="Summarize the key findings in this case">
                            <i class="fas fa-lightbulb"></i> Summarize Findings
                        </button>
                        <button class="suggestion-btn" data-query="What are the most suspicious indicators?">
                            <i class="fas fa-exclamation-triangle"></i> Suspicious Indicators
                        </button>
                        <button class="suggestion-btn" data-query="Identify potential connections between indicators">
                            <i class="fas fa-project-diagram"></i> Find Connections
                        </button>
                        <button class="suggestion-btn" data-query="What should I investigate next?">
                            <i class="fas fa-question-circle"></i> Next Steps
                        </button>
                    </div>
                    <div class="ai-assistant-input-wrapper">
                        <textarea id="ai-assistant-input" 
                                  class="ai-assistant-input" 
                                  placeholder="Ask about the case data, indicators, or request analysis..."
                                  rows="2"></textarea>
                        <button id="ai-assistant-send" class="ai-assistant-send">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add welcome message
        this.addMessage('assistant', 'Hello! I can help you analyze your case data. Ask me questions about indicators, patterns, or request summaries. You can also use the suggestion buttons above.');
    }

    attachEventListeners() {
        const toggle = document.getElementById('ai-assistant-toggle');
        const close = document.getElementById('ai-assistant-close');
        const send = document.getElementById('ai-assistant-send');
        const input = document.getElementById('ai-assistant-input');
        const suggestions = document.querySelectorAll('.suggestion-btn');

        if (toggle) {
            toggle.addEventListener('click', () => this.toggle());
        }

        if (close) {
            close.addEventListener('click', () => this.toggle());
        }

        if (send) {
            send.addEventListener('click', () => this.sendMessage());
        }

        if (input) {
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage();
                }
            });
        }

        suggestions.forEach(btn => {
            btn.addEventListener('click', () => {
                const query = btn.getAttribute('data-query');
                if (query) {
                    input.value = query;
                    this.sendMessage();
                }
            });
        });
    }

    toggle() {
        this.isOpen = !this.isOpen;
        const panel = document.getElementById('ai-assistant-panel');
        if (panel) {
            panel.style.display = this.isOpen ? 'block' : 'none';
        }
        if (this.isOpen) {
            const input = document.getElementById('ai-assistant-input');
            if (input) input.focus();
        }
    }

    addMessage(role, content, isLoading = false) {
        const messagesContainer = document.getElementById('ai-assistant-messages');
        if (!messagesContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `ai-message ai-message-${role}`;
        
        if (isLoading) {
            messageDiv.innerHTML = `
                <div class="ai-message-content">
                    <div class="ai-loading">
                        <div class="spinner"></div>
                        <span>Thinking...</span>
                    </div>
                </div>
            `;
        } else {
            const icon = role === 'user' ? 'fa-user' : 'fa-robot';
            messageDiv.innerHTML = `
                <div class="ai-message-content">
                    <i class="fas ${icon}"></i>
                    <div class="ai-message-text">${this.formatMessage(content)}</div>
                </div>
            `;
        }

        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    formatMessage(content) {
        // Convert markdown-like formatting to HTML
        return content
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/\n/g, '<br>');
    }

    async sendMessage() {
        const input = document.getElementById('ai-assistant-input');
        if (!input || !input.value.trim()) return;

        const userMessage = input.value.trim();
        input.value = '';
        
        this.addMessage('user', userMessage);
        this.addMessage('assistant', '', true);

        try {
            const response = await fetch(this.apiEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    project_name: this.projectName,
                    message: userMessage,
                    conversation_history: this.conversationHistory.slice(-10) // Last 10 messages for context
                })
            });

            const data = await response.json();
            
            // Remove loading message
            const messagesContainer = document.getElementById('ai-assistant-messages');
            if (messagesContainer) {
                const loadingMessage = messagesContainer.querySelector('.ai-loading');
                if (loadingMessage) {
                    loadingMessage.closest('.ai-message').remove();
                }
            }

            if (data.success) {
                this.addMessage('assistant', data.response);
                this.conversationHistory.push({ role: 'user', content: userMessage });
                this.conversationHistory.push({ role: 'assistant', content: data.response });
            } else {
                this.addMessage('assistant', `Error: ${data.error || 'Failed to get AI response'}`);
            }
        } catch (error) {
            // Remove loading message
            const messagesContainer = document.getElementById('ai-assistant-messages');
            if (messagesContainer) {
                const loadingMessage = messagesContainer.querySelector('.ai-loading');
                if (loadingMessage) {
                    loadingMessage.closest('.ai-message').remove();
                }
            }
            
            this.addMessage('assistant', `Error: ${error.message || 'Failed to connect to AI service'}`);
        }
    }
}

