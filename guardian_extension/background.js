// background.js - Monitors browser tabs for AI tools

// Complete list of AI websites to detect
const AI_WEBSITES = [
  // OpenAI / ChatGPT
  { url: 'chat.openai.com', name: 'ChatGPT' },
  { url: 'chatgpt.com', name: 'ChatGPT' },
  { url: 'platform.openai.com', name: 'OpenAI' },
  { url: 'openai.com', name: 'OpenAI' },
  
  // Anthropic Claude
  { url: 'claude.ai', name: 'Claude' },
  
  // Google
  { url: 'gemini.google.com', name: 'Gemini' },
  { url: 'bard.google.com', name: 'Bard' },
  
  // DeepSeek
  { url: 'deepseek.com', name: 'DeepSeek' },
  { url: 'chat.deepseek.com', name: 'DeepSeek' },
  
  // Perplexity
  { url: 'perplexity.ai', name: 'Perplexity' },
  
  // Microsoft Copilot
  { url: 'copilot.microsoft.com', name: 'Copilot' },
  { url: 'bing.com/chat', name: 'Copilot' },
  
  // Mistral
  { url: 'mistral.ai', name: 'Mistral' },
  { url: 'chat.mistral.ai', name: 'Mistral' },
  
  // Other AI Tools
  { url: 'you.com', name: 'You.com' },
  { url: 'poe.com', name: 'Poe' },
  { url: 'character.ai', name: 'Character AI' },
  { url: 'pi.ai', name: 'Pi' },
  { url: 'inflection.ai', name: 'Inflection' },
  { url: 'cohere.com', name: 'Cohere' },
  { url: 'huggingface.co', name: 'Hugging Face' },
  { url: 'replicate.com', name: 'Replicate' }
];

// Store detected AI models
let detectedAIs = {};

// Function to check if URL is an AI website
function isAIWebsite(url) {
  if (!url) return null;
  const urlLower = url.toLowerCase();
  
  for (const site of AI_WEBSITES) {
    if (urlLower.includes(site.url)) {
      return site;
    }
  }
  return null;
}

// Function to send detection to Python server
function sendToPythonTool(action, aiName, tabId, url, title) {
  const data = {
    action: action,
    model_name: aiName,
    type: 'Browser',
    tab_id: tabId,
    url: url || '',
    title: title || '',
    timestamp: new Date().toISOString()
  };
  
  // Send to Python server
  fetch('http://localhost:5000/api/detect', {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })
  .then(response => response.json())
  .then(data => {
    console.log(`✅ ${action === 'add' ? 'Added' : 'Removed'}:`, data);
  })
  .catch(error => {
    console.log('⚠️ Server not running (start with: python extension_server.py)');
  });
}

// ============================================
// DETECT WHEN TAB IS CLOSED
// ============================================
chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
  if (detectedAIs[tabId]) {
    const modelInfo = detectedAIs[tabId];
    console.log(`❌ Tab CLOSED: ${modelInfo.name}`);
    
    sendToPythonTool('remove', modelInfo.name, tabId, modelInfo.url, modelInfo.title);
    delete detectedAIs[tabId];
    
    const count = Object.keys(detectedAIs).length;
    chrome.action.setBadgeText({ text: count > 0 ? count.toString() : '' });
  }
});

// ============================================
// DETECT WHEN TAB IS UPDATED
// ============================================
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'complete') {
    const url = tab.url || changeInfo.url;
    if (url) {
      const aiSite = isAIWebsite(url);
      if (aiSite) {
        if (detectedAIs[tabId]) return;
        
        detectedAIs[tabId] = {
          name: aiSite.name,
          url: url,
          title: tab.title || '',
          detected_at: new Date().toISOString()
        };
        
        sendToPythonTool('add', aiSite.name, tabId, url, tab.title);
        
        const count = Object.keys(detectedAIs).length;
        chrome.action.setBadgeText({ text: count.toString() });
        chrome.action.setBadgeBackgroundColor({ color: '#00d4ff' });
        
        console.log(`🟢 AI Detected: ${aiSite.name}`);
      } else {
        if (detectedAIs[tabId]) {
          const modelInfo = detectedAIs[tabId];
          console.log(`🔄 Tab NAVIGATED AWAY: ${modelInfo.name}`);
          
          sendToPythonTool('remove', modelInfo.name, tabId, modelInfo.url, modelInfo.title);
          delete detectedAIs[tabId];
          
          const count = Object.keys(detectedAIs).length;
          chrome.action.setBadgeText({ text: count > 0 ? count.toString() : '' });
        }
      }
    }
  }
});

// ============================================
// DETECT WHEN TAB IS CREATED
// ============================================
chrome.tabs.onCreated.addListener((tab) => {
  if (tab.url && tab.url !== 'chrome://newtab/' && tab.url !== 'about:blank') {
    const aiSite = isAIWebsite(tab.url);
    if (aiSite) {
      detectedAIs[tab.id] = {
        name: aiSite.name,
        url: tab.url,
        title: tab.title || '',
        detected_at: new Date().toISOString()
      };
      
      sendToPythonTool('add', aiSite.name, tab.id, tab.url, tab.title);
      
      const count = Object.keys(detectedAIs).length;
      chrome.action.setBadgeText({ text: count.toString() });
      
      console.log(`🟢 AI Detected (new tab): ${aiSite.name}`);
    }
  }
});

// ============================================
// LISTEN FOR MESSAGES FROM POPUP
// ============================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getDetectedAIs') {
    const results = Object.values(detectedAIs);
    sendResponse({ ais: results });
    return true;
  }
  
  if (message.action === 'refreshDetection') {
    chrome.tabs.query({}, (tabs) => {
      let count = 0;
      for (const tab of tabs) {
        if (tab.url) {
          const aiSite = isAIWebsite(tab.url);
          if (aiSite && !detectedAIs[tab.id]) {
            detectedAIs[tab.id] = {
              name: aiSite.name,
              url: tab.url,
              title: tab.title || '',
              detected_at: new Date().toISOString()
            };
            sendToPythonTool('add', aiSite.name, tab.id, tab.url, tab.title);
            count++;
          }
        }
      }
      console.log(`🔄 Refresh complete: ${count} new AI tools detected`);
      const total = Object.keys(detectedAIs).length;
      chrome.action.setBadgeText({ text: total.toString() });
      sendResponse({ success: true, count: total });
    });
    return true;
  }
  
  if (message.action === 'clearDetection') {
    detectedAIs = {};
    chrome.action.setBadgeText({ text: '' });
    sendResponse({ success: true });
    return true;
  }
});

// ============================================
// INITIAL SCAN
// ============================================
chrome.tabs.query({}, (tabs) => {
  let count = 0;
  for (const tab of tabs) {
    if (tab.url && tab.url !== 'chrome://newtab/' && tab.url !== 'about:blank') {
      const aiSite = isAIWebsite(tab.url);
      if (aiSite) {
        detectedAIs[tab.id] = {
          name: aiSite.name,
          url: tab.url,
          title: tab.title || '',
          detected_at: new Date().toISOString()
        };
        sendToPythonTool('add', aiSite.name, tab.id, tab.url, tab.title);
        count++;
      }
    }
  }
  if (count > 0) {
    chrome.action.setBadgeText({ text: count.toString() });
    console.log(`🛡️ Initial scan complete: ${count} AI tools detected`);
  }
});

// ============================================
// PERIODIC SYNC (Every 10 seconds)
// ============================================
setInterval(() => {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.url && tab.url !== 'chrome://newtab/' && tab.url !== 'about:blank') {
        const aiSite = isAIWebsite(tab.url);
        if (aiSite) {
          if (!detectedAIs[tab.id]) {
            detectedAIs[tab.id] = {
              name: aiSite.name,
              url: tab.url,
              title: tab.title || '',
              detected_at: new Date().toISOString()
            };
          }
          // Periodically send 'add' as a heartbeat in case Python server restarted
          sendToPythonTool('add', aiSite.name, tab.id, tab.url, tab.title);
        }
      }
    }
    const count = Object.keys(detectedAIs).length;
    chrome.action.setBadgeText({ text: count > 0 ? count.toString() : '' });
  });
}, 10000);

console.log('🛡️ Guardian AI Detector Extension Started!');
console.log('📋 Watching for AI tools in real-time...');