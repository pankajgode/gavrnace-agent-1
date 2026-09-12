// guardian_extension/content.js
// REAL-TIME TOOL DETECTION - This makes everything work!

console.log('🟢 Guardian Agent: Content script loaded!');

// ============================================
// CONFIGURATION
// ============================================

const API_URL = 'http://localhost:5001/api/tool_event';
let lastDetected = {};

// ============================================
// DETECT TOOL CALLS FROM THE PAGE
// ============================================

function detectToolCalls() {
    const url = window.location.href;
    let agentId = getAgentId(url);
    
    // Method 1: Check for code blocks (Python, JS, etc.)
    detectCodeBlocks(agentId);
    
    // Method 2: Check for search indicators
    detectSearchIndicators(agentId);
    
    // Method 3: Check for file operations
    detectFileOperations(agentId);
    
    // Method 4: Check for "thinking" or "processing" indicators
    detectThinkingIndicators(agentId);
}

// ============================================
// DETECT CODE BLOCKS
// ============================================

function detectCodeBlocks(agentId) {
    const codeBlocks = document.querySelectorAll('pre code, code, .code-block, .hljs, .language-python, .language-javascript');
    
    for (const block of codeBlocks) {
        const text = block.innerText || '';
        const className = block.className || '';
        
        // Python code detection
        if (className.includes('python') || text.includes('import ') || text.includes('def ') || text.includes('class ')) {
            if (!lastDetected['code_runner'] || Date.now() - lastDetected['code_runner'] > 5000) {
                sendToolEvent(agentId, 'code_runner', 'execute:python', text.substring(0, 200));
                lastDetected['code_runner'] = Date.now();
                showIndicator('🐍 Python code detected');
            }
        }
        
        // JavaScript code detection
        if (className.includes('javascript') || className.includes('js') || text.includes('function ') || text.includes('const ') || text.includes('let ')) {
            if (!lastDetected['code_runner'] || Date.now() - lastDetected['code_runner'] > 5000) {
                sendToolEvent(agentId, 'code_runner', 'execute:javascript', text.substring(0, 200));
                lastDetected['code_runner'] = Date.now();
                showIndicator('🟨 JavaScript detected');
            }
        }
    }
}

// ============================================
// DETECT SEARCH INDICATORS
// ============================================

function detectSearchIndicators(agentId) {
    const searchKeywords = ['searching', 'searching for', 'looking up', 'finding', 'fetching', 'browsing', 'scraping'];
    const elements = document.querySelectorAll('div, p, span, .message, .assistant-message, .response');
    
    for (const el of elements) {
        const text = el.innerText || '';
        const lowerText = text.toLowerCase();
        
        for (const keyword of searchKeywords) {
            if (lowerText.includes(keyword)) {
                if (!lastDetected['web_searcher'] || Date.now() - lastDetected['web_searcher'] > 5000) {
                    sendToolEvent(agentId, 'web_searcher', 'search:web', text.substring(0, 100));
                    lastDetected['web_searcher'] = Date.now();
                    showIndicator('🔍 Web search detected');
                    break;
                }
            }
        }
    }
}

// ============================================
// DETECT FILE OPERATIONS
// ============================================

function detectFileOperations(agentId) {
    const fileKeywords = ['reading file', 'reading', 'opening', 'accessing', '/etc/', '/home/', 'C:\\', 'file://'];
    const elements = document.querySelectorAll('div, p, span, pre, code');
    
    for (const el of elements) {
        const text = el.innerText || '';
        const lowerText = text.toLowerCase();
        
        for (const keyword of fileKeywords) {
            if (lowerText.includes(keyword)) {
                // Extract file path
                const fileMatch = text.match(/(\/[a-zA-Z0-9_\-\.\/]+|[A-Z]:\\[a-zA-Z0-9_\-\.\\]+)/);
                const target = fileMatch ? fileMatch[0] : text.substring(0, 100);
                
                if (!lastDetected['file_reader'] || Date.now() - lastDetected['file_reader'] > 5000) {
                    sendToolEvent(agentId, 'file_reader', 'read:file', target);
                    lastDetected['file_reader'] = Date.now();
                    showIndicator('📄 File operation detected');
                    break;
                }
            }
        }
    }
}

// ============================================
// DETECT "THINKING" OR "PROCESSING" INDICATORS
// ============================================

function detectThinkingIndicators(agentId) {
    const thinkingKeywords = ['thinking', 'processing', 'analyzing', 'working on it', 'generating'];
    const elements = document.querySelectorAll('div, p, span, .status, .typing');
    
    for (const el of elements) {
        const text = el.innerText || '';
        const lowerText = text.toLowerCase();
        
        for (const keyword of thinkingKeywords) {
            if (lowerText.includes(keyword)) {
                if (!lastDetected['analyzer'] || Date.now() - lastDetected['analyzer'] > 5000) {
                    sendToolEvent(agentId, 'analyzer', 'analyze:data', text.substring(0, 100));
                    lastDetected['analyzer'] = Date.now();
                    showIndicator('🧠 Analysis in progress');
                    break;
                }
            }
        }
    }
}

// ============================================
// GET AGENT ID FROM URL
// ============================================

function getAgentId(url) {
    if (url.includes('deepseek.com')) return 'deepseek_browser';
    if (url.includes('chat.openai.com')) return 'chatgpt_browser';
    if (url.includes('claude.ai')) return 'claude_browser';
    if (url.includes('gemini.google.com')) return 'gemini_browser';
    if (url.includes('perplexity.ai')) return 'perplexity_browser';
    return 'unknown_browser';
}

// ============================================
// SEND TOOL EVENT TO SERVER
// ============================================

function sendToolEvent(agentId, subAgentName, actionType, target) {
    console.log(`🔄 Sending: ${subAgentName} → ${actionType} (${agentId})`);
    
    const eventData = {
        agent_id: agentId,
        sub_agent_name: subAgentName,
        tool_name: subAgentName,
        action_type: actionType,
        target: target || 'unknown',
        timestamp: new Date().toISOString()
    };
    
    fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(eventData)
    })
    .then(response => response.json())
    .then(data => {
        console.log(`✅ Tool event recorded: ${subAgentName}`);
    })
    .catch(error => {
        console.log(`⚠️ Tool event failed: ${error.message}`);
        // Show the error in the UI
        showIndicator('❌ Server not running!');
    });
}

// ============================================
// SHOW VISUAL INDICATOR ON PAGE
// ============================================

function showIndicator(message) {
    let indicator = document.getElementById('guardian-indicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'guardian-indicator';
        indicator.style.cssText = `
            position: fixed;
            bottom: 10px;
            right: 10px;
            background: #00ff00;
            color: #000;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 11px;
            z-index: 999999;
            font-family: monospace;
            opacity: 0.9;
            transition: opacity 0.5s;
            pointer-events: none;
        `;
        document.body.appendChild(indicator);
    }
    
    indicator.textContent = `🟢 ${message}`;
    indicator.style.opacity = '1';
    
    // Fade out after 2 seconds
    clearTimeout(indicator._timeout);
    indicator._timeout = setTimeout(() => {
        indicator.style.opacity = '0.3';
    }, 2000);
}

// ============================================
// RUN DETECTION EVERY 2 SECONDS
// ============================================

console.log('🟢 Guardian Agent: Starting detection...');

// Run detection every 2 seconds
setInterval(detectToolCalls, 2000);

// Also detect on page changes (SPA navigation)
let lastUrl = location.href;
const observer = new MutationObserver(() => {
    if (location.href !== lastUrl) {
        lastUrl = location.href;
        console.log(`🔄 Page changed to: ${lastUrl}`);
        setTimeout(detectToolCalls, 1000);
    }
});
observer.observe(document, { subtree: true, childList: true });

// Run once immediately
setTimeout(detectToolCalls, 1000);

console.log('✅ Guardian Agent: Content script ready!');