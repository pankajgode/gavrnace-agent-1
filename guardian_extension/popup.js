// popup.js - Shows detected AI tools

document.addEventListener('DOMContentLoaded', () => {
  const aiList = document.getElementById('aiList');
  
  // Request detected AIs from background script
  chrome.runtime.sendMessage({ action: 'getDetectedAIs' }, (response) => {
    if (response && response.ais.length > 0) {
      aiList.innerHTML = '';
      
      for (const ai of response.ais) {
        const div = document.createElement('div');
        div.className = 'ai-item';
        div.innerHTML = `
          <div class="ai-name">🤖 ${ai.name}</div>
          <div class="ai-url">${ai.url}</div>
          <div class="status">🟢 Active</div>
        `;
        aiList.appendChild(div);
      }
    } else {
      aiList.innerHTML = `
        <div class="no-ai">
          🌐 No AI tools detected<br>
          <span style="font-size: 11px;">Open ChatGPT, Claude, or Gemini</span>
        </div>
      `;
    }
  });
});