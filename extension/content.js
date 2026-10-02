// Codentia Content Script
// Injects into web pages, monitors AI chat outputs, enforces active rules, validates against Moss WASM & Truth Layer

let rules = [];
let extensionEnabled = true;
let mossActive = false;
let processedNodes = new WeakSet();
let currentStats = { totalChecks: 0, violationsCaught: 0 };

// Initialize
function init() {
  if (window.location.hostname.includes('github.com') || window.location.hostname.includes('vercel.app')) {
    console.log("[Codentia] Repository/Development domain detected — skipping extension monitoring.");
    return;
  }

  chrome.runtime.sendMessage({ action: "getRules" }, (response) => {
    if (response) {
      rules = response.rules || [];
      extensionEnabled = response.enabled !== false;
      mossActive = response.mossActive === true;
      console.log(`[Codentia] Loaded ${rules.length} rules, enabled: ${extensionEnabled}, Moss: ${mossActive ? 'SEMANTIC' : 'keyword fallback'}`);
      startMonitoring();
      setupPreInjection();
    }
  });
}

// Listen for rule updates from background
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === "rulesUpdated") {
    rules = message.rules || [];
    if (message.mossActive !== undefined) mossActive = message.mossActive;
    console.log(`[Codentia] Rules updated: ${rules.length}, Moss: ${mossActive}`);
  } else if (message.action === "enabledUpdated") {
    extensionEnabled = message.enabled;
    console.log("[Codentia] Enabled:", extensionEnabled);
  }
});

// ============================================================
// DELIVERABLE 1 — PRE-INJECTION SYSTEM
// Appends active rules to EVERY user prompt with 5 lines of space
// Format: prompt + 5 lines space + "[ENFORCE: rule1; rule2; rule3]"
// Works on ChatGPT, Claude, Gemini, Grok, Perplexity, DeepSeek
// ============================================================
function setupPreInjection() {
  // Codentia V2: pre-send policy gateway.
  // PII is masked before the page receives the submit event; secrets are blocked.
  const getActiveRules = () => rules.filter(r => r.enabled);

  const findActiveInput = () => {
    const selectors = [
      '#prompt-textarea',
      'div[contenteditable="true"]',
      '.ProseMirror',
      '[role="textbox"]',
      'textarea',
      'input[type="text"]'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && (el.offsetWidth > 0 || el.offsetHeight > 0)) return el;
    }
    return document.activeElement;
  };

  const readInput = (el) => {
    if (!el) return '';
    return (el.value !== undefined ? el.value : el.innerText || el.textContent || '').trim();
  };

  const writeInput = (el, text) => {
    if (!el) return;
    if (el.value !== undefined) {
      const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value')?.set;
      if (setter) setter.call(el, text); else el.value = text;
      el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
      return;
    }
    el.textContent = text;
    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
  };

  const getRuleString = () => {
    const active = getActiveRules().filter(r => r.type !== 'privacy' && r.type !== 'secret');
    if (!active.length) return '';
    return `[ENFORCE: ${active.map(r => r.text).join('; ')}]`;
  };

  const inspectPrompt = (text) => {
    const findings = detectSensitiveData(text);
    const secret = findings.find(f => f.category === 'secret');
    const pii = findings.filter(f => f.category === 'pii');
    return { findings, secret, pii };
  };

  const handlePromptSubmit = (event) => {
    if (!extensionEnabled) return;
    const inputEl = findActiveInput();
    if (!inputEl) return;
    const original = readInput(inputEl);
    if (!original) return;

    const inspection = inspectPrompt(original);

    // Hard protection: don't allow likely secrets to leave the browser.
    if (inspection.secret) {
      event.preventDefault();
      event.stopImmediatePropagation();
      showPolicyToast('blocked', 'Secret detected', 'Codentia stopped this prompt because it contains a possible API key, password, or access token.');
      logPreflight('blocked', inspection.findings);
      return;
    }

    // Privacy protection: mask PII before the website sees the submit event.
    let safeText = original;
    if (inspection.pii.length > 0) {
      safeText = maskSensitiveData(safeText, inspection.pii);
      writeInput(inputEl, safeText);
      showPolicyToast('masked', 'Sensitive data masked', `${inspection.pii.length} sensitive item${inspection.pii.length === 1 ? '' : 's'} masked before sending.`);
      logPreflight('masked', inspection.pii);
    }

    // Keep the existing policy injection as a second layer.
    const ruleString = getRuleString();
    if (ruleString && !safeText.includes('[ENFORCE:')) {
      const injected = `${safeText}\n\n\n\n\n${ruleString}`;
      writeInput(inputEl, injected);
    }
  };

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) handlePromptSubmit(e);
  }, true);

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button, [role="button"]');
    if (!btn) return;
    const label = `${btn.textContent || ''} ${btn.getAttribute('aria-label') || ''} ${btn.getAttribute('data-testid') || ''}`.toLowerCase();
    if (label.includes('send') || label.includes('submit') || label.includes('prompt-submit') || btn.querySelector('svg')) {
      handlePromptSubmit(e);
    }
  }, true);
}

// -------------------- CODENTIA V2 PRIVACY GATE --------------------
const SENSITIVE_PATTERNS = [
  { category: 'secret', label: 'API key / token', regex: /\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, replacement: '[SECRET REDACTED]' },
  { category: 'secret', label: 'Credential assignment', regex: /\b(?:api[_-]?key|secret|password|passwd|access[_-]?token)\s*[:=]\s*[^\s,;]+/gi, replacement: '[SECRET REDACTED]' },
  { category: 'pii', label: 'Email address', regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: '[EMAIL REDACTED]' },
  { category: 'pii', label: 'Phone number', regex: /(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)/g, replacement: '[PHONE REDACTED]' },
  { category: 'pii', label: 'Credit card number', regex: /\b(?:\d[ -]*?){13,19}\b/g, replacement: '[CARD REDACTED]' },
  { category: 'pii', label: 'Indian PAN', regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, replacement: '[PAN REDACTED]' },
  { category: 'pii', label: 'Indian Aadhaar-like number', regex: /(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)/g, replacement: '[ID REDACTED]' }
];

function detectSensitiveData(text) {
  const findings = [];
  for (const p of SENSITIVE_PATTERNS) {
    const matches = text.match(p.regex);
    if (matches) {
      [...new Set(matches)].slice(0, 10).forEach(value => findings.push({ category: p.category, label: p.label, value, replacement: p.replacement }));
    }
  }
  return findings;
}

function maskSensitiveData(text, findings) {
  let safe = text;
  findings.forEach(f => {
    const escaped = f.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    safe = safe.replace(new RegExp(escaped, 'g'), f.replacement);
  });
  return safe;
}

function logPreflight(action, findings) {
  try { chrome.runtime.sendMessage({ action: 'logPreflight', result: action, findings: findings.map(f => ({ category: f.category, label: f.label })) }); } catch (_) {}
}

function showPolicyToast(kind, title, message) {
  const old = document.querySelector('.codentia-policy-toast');
  if (old) old.remove();
  const toast = document.createElement('div');
  toast.className = 'codentia-policy-toast';
  const icon = kind === 'blocked' ? '🛑' : kind === 'masked' ? '🔐' : '✓';
  toast.innerHTML = `<strong>${icon} ${escapeHtml(title)}</strong><span>${escapeHtml(message)}</span>`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4500);
}

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = value;
  return div.innerHTML;
}


// Format 5 vertical lines of space before [ENFORCE: ...] in user prompt speech bubbles across ALL LLMs
function formatEnforceSpacingInUserBubbles() {
  document.querySelectorAll('*').forEach(el => {
    if (el.children.length === 0 && el.textContent && el.textContent.includes('[ENFORCE:') && !el.getAttribute('data-codentia-spaced')) {
      const isInputOrForm = el.closest('form, .input-area, [contenteditable="true"], textarea, input, #prompt-textarea');
      if (!isInputOrForm) {
        el.setAttribute('data-codentia-spaced', 'true');
        const text = el.textContent;
        const idx = text.indexOf('[ENFORCE:');
        if (idx > 0) {
          const promptPart = text.substring(0, idx).trim();
          const enforcePart = text.substring(idx).trim();
          el.innerHTML = `${promptPart}<br><br><br><br><br><span>${enforcePart}</span>`;
        }
      }
    }
  });
}

// Start monitoring DOM for AI chat output
function startMonitoring() {
  const observer = new MutationObserver((mutations) => {
    if (!extensionEnabled) return;
    formatEnforceSpacingInUserBubbles();

    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (isLikelyAIResponse(node)) {
            handleStreamingOrFullResponse(node);
          }
          node.querySelectorAll && node.querySelectorAll('*').forEach(child => {
            if (isLikelyAIResponse(child) && !processedNodes.has(child)) {
              handleStreamingOrFullResponse(child);
            }
          });
        } else if (mutation.type === 'characterData' && mutation.target.parentElement) {
          const parent = mutation.target.parentElement.closest('*');
          if (parent && isLikelyAIResponse(parent)) {
            handleStreamingOrFullResponse(parent);
          }
        }
      });
    });
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true
  });

  // Scan existing content
  document.querySelectorAll('*').forEach(el => {
    if (isLikelyAIResponse(el)) handleStreamingOrFullResponse(el);
  });

  console.log("[Codentia] Universal monitoring active — " + (mossActive ? "Moss WASM mode" : "keyword fallback mode"));
}

// Universal Heuristic: Explicitly detect AI response elements for ChatGPT, Claude, Gemini, Grok, Perplexity & DeepSeek
function isLikelyAIResponse(el) {
  if (!el || !el.textContent || el.textContent.trim().length < 20) return false;

  const tagName = el.tagName.toLowerCase();
  if (['input', 'textarea', 'form', 'button', 'script', 'style', 'nav', 'header'].includes(tagName)) return false;
  if (el.getAttribute && el.getAttribute('contenteditable') === 'true') return false;
  if (el.closest && (el.closest('form') || el.closest('.input-area') || el.closest('[contenteditable="true"]') || el.closest('user-query'))) return false;

  // EXCLUDE User message containers across ChatGPT, Claude, Gemini, Grok, Perplexity
  const classNames = el.className ? String(el.className).toLowerCase() : '';
  const idStr = el.id ? String(el.id).toLowerCase() : '';
  const parentClass = el.parentElement?.className ? String(el.parentElement.className).toLowerCase() : '';
  const authorRole = el.getAttribute ? (el.getAttribute('data-message-author-role') || '').toLowerCase() : '';

  if (authorRole === 'user') return false;
  if (classNames.includes('user') || parentClass.includes('user') || idStr.includes('user')) return false;
  if (el.closest && (
    el.closest('[data-message-author-role="user"]') ||
    el.closest('.user-message') ||
    el.closest('.font-user-message') ||
    el.closest('[data-testid="user-message"]') ||
    el.closest('user-query')
  )) return false;

  // DETECT Assistant/Model AI Messages
  if (authorRole === 'assistant') return true;

  const aiIndicators = [
    'assistant', 'font-claude-message', 'message-ai', 'ai-message', 'bot-message',
    'chat-response', 'model-response', 'response-container-content',
    'agent-turn', 'claude', 'gpt', 'gemini', 'grok', 'copilot'
  ];

  const hasAIIndicator = aiIndicators.some(ind =>
    classNames.includes(ind) || parentClass.includes(ind) || idStr.includes(ind)
  );

  const hasDemoMarker = el.id === 'demo-ai-response' ||
    el.classList.contains('demo-ai-response') ||
    (el.getAttribute && el.getAttribute('data-ai-response') === 'true');

  const isProseContainer = (classNames.includes('prose') || classNames.includes('markdown')) &&
    !classNames.includes('user') &&
    el.textContent.length > 35;

  return hasAIIndicator || hasDemoMarker || isProseContainer;
}

// Real-time streaming enforcement + Post-generation validation
function handleStreamingOrFullResponse(element) {
  enforceStreamingWordLimit(element);

  if (element.codentiaTimer) clearTimeout(element.codentiaTimer);
  element.codentiaTimer = setTimeout(() => {
    processAIResponse(element);
  }, 400);
}

// ============================================================
// STREAMING ENFORCEMENT & WARNING PLACEMENT
// Appends warning marker cleanly at the VERY BOTTOM of the AI response card
// ============================================================
function enforceStreamingWordLimit(element) {
  const lengthRule = rules.find(r => r.enabled && r.type === 'length');
  if (!lengthRule) return;

  const limitMatch = lengthRule.text.match(/(\d+)\s*words?/i);
  const limit = limitMatch ? parseInt(limitMatch[1]) : 50;

  const fullText = element.textContent || '';
  const words = fullText.trim().split(/\s+/);

  if (words.length > limit) {
    if (!element.querySelector('.codentia-warning')) {
      const warningMarker = document.createElement('div');
      warningMarker.className = 'codentia-violation codentia-warning';
      warningMarker.style.cssText = 'background:rgba(255,107,107,0.12);color:#D64545;font-size:12px;font-weight:600;padding:6px 12px;border-radius:6px;margin-top:8px;display:inline-block;';
      warningMarker.title = `Codentia Enforcement: Exceeded ${limit} words limit (${words.length} words total)`;
      warningMarker.textContent = `⚠ Exceeded length limit of ${limit} words (${words.length} words typed)`;
      element.appendChild(warningMarker);
      console.log(`[Codentia] Streaming enforcement triggered cleanly at bottom: ${words.length} > ${limit} words`);
    }
  }
}

// Process full AI response (Dual Path Validation + Truth Layer Verification)
async function processAIResponse(element) {
  if (processedNodes.has(element)) return;
  processedNodes.add(element);

  const text = element.textContent;
  if (!text || text.trim().length < 20) return;

  // POST-CHECK: prevent sensitive data from remaining visible in the AI response.
  const outputFindings = detectSensitiveData(text);
  if (outputFindings.length > 0) {
    redactSensitiveNodes(element, outputFindings);
    chrome.runtime.sendMessage({ action: "logPreflight", result: "output-redacted", findings: outputFindings.map(f => ({ category: f.category, label: f.label })) });
  }

  let violations = [];
  let usedMoss = false;
  let latencyMs = null;

  // DUAL VALIDATION PATH (Run both Semantic & Keyword, prioritize Semantic if confidence > 0.7)
  let keywordViolations = validateTextKeyword(text);
  let semanticViolations = [];

  if (mossActive) {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({
          action: "validateSemantic",
          text: text,
          context: text.substring(0, 200)
        }, resolve);
      });

      if (response && response.mossActive && response.violations) {
        semanticViolations = response.violations;
        usedMoss = true;
        latencyMs = response.latencyMs;
      }
    } catch (e) {
      console.warn("[Codentia] Moss query failed, falling back to keywords:", e);
    }
  }

  // Combine & prioritize results (Semantic overrides if confidence > 0.7)
  if (usedMoss && semanticViolations.length > 0 && semanticViolations[0].confidence > 0.7) {
    violations = semanticViolations;
  } else {
    violations = keywordViolations;
    usedMoss = false;
  }

  // TRUTH LAYER FACT VERIFICATION (Deliverable 3)
  let truthData = null;
  try {
    truthData = await new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: "verifyClaims",
        text: text
      }, resolve);
    });
  } catch (e) {}

  // Apply visual feedback & badges cleanly at bottom into EXISTING UI
  if (violations.length > 0) {
    highlightViolations(element, violations, usedMoss);
    chrome.runtime.sendMessage({ action: "logViolation", latencyMs });
    currentStats.violationsCaught++;
    showComplianceBadge(element, violations, usedMoss, latencyMs, truthData);
  } else {
    chrome.runtime.sendMessage({ action: "logCheck" });
    showCleanBadge(element, usedMoss, truthData);
  }

  // Highlight Truth Layer contradictions if found
  if (truthData && truthData.claims) {
    truthData.claims.filter(c => c.status === 'contradiction').forEach(c => {
      highlightContradiction(element, c);
    });
  }

  currentStats.totalChecks++;
}

function redactSensitiveNodes(element, findings) {
  try {
    const replacements = findings.map(f => ({ value: f.value, replacement: f.replacement }));
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
    const nodes = [];
    let node;
    while ((node = walker.nextNode())) nodes.push(node);
    nodes.forEach(textNode => {
      let text = textNode.textContent;
      let changed = false;
      replacements.forEach(r => {
        if (text.includes(r.value)) {
          text = text.split(r.value).join(r.replacement);
          changed = true;
        }
      });
      if (changed) textNode.textContent = text;
    });
    const banner = document.createElement('div');
    banner.className = 'codentia-output-protection';
    banner.innerHTML = '<strong>🔐 Codentia protected this response</strong><span>Sensitive information detected and redacted by the post-response policy check.</span>';
    element.appendChild(banner);
  } catch (_) {}
}

// Keyword Validation Baseline
function validateTextKeyword(text) {
  const violations = [];
  const lowerText = text.toLowerCase();

  rules.filter(r => r.enabled).forEach(rule => {
    switch (rule.type) {
      case "forbidden":
        if (rule.keywords && rule.keywords.length > 0) {
          rule.keywords.forEach(keyword => {
            if (lowerText.includes(keyword.toLowerCase())) {
              violations.push({
                rule: rule.text,
                keyword: keyword,
                type: "forbidden",
                matchedText: findMatch(text, keyword),
                semantic: false
              });
            }
          });
        } else {
          const entityMatch = rule.text.match(/(?:never|don't|do not)\s+mention\s+(.+?)(?:\.|$|,)/i);
          const targetTerm = entityMatch ? entityMatch[1].trim().toLowerCase() : null;
          if (targetTerm && lowerText.includes(targetTerm)) {
            violations.push({
              rule: rule.text,
              type: "forbidden",
              matchedText: findMatch(text, targetTerm),
              semantic: false
            });
          }
        }
        break;

      case "length":
        const limitMatch = rule.text.match(/(\d+)\s*words?/i);
        const limit = limitMatch ? parseInt(limitMatch[1]) : 50;
        const words = text.trim().split(/\s+/);
        if (words.length > limit) {
          violations.push({
            rule: rule.text,
            type: "length",
            wordCount: words.length,
            limit: limit,
            semantic: false
          });
        }
        break;

      case "format":
        if (rule.text.toLowerCase().includes("bullet")) {
          const hasBullets = /[•\-*]/.test(text) || /^\s*\d+\./m.test(text);
          if (!hasBullets && text.split(/\s+/).length > 20) {
            violations.push({
              rule: rule.text,
              type: "format",
              issue: "No bullet points found",
              semantic: false
            });
          }
        }
        break;

      case "citation":
        const hasCitation = /\[(?:\d+|[^\]]+\))\]|\(https?:\/\/[^\)]+\)|source:|cited from/i.test(text);
        if (!hasCitation && /\d{4}|\d+%|according to|research shows/i.test(text)) {
          violations.push({
            rule: rule.text,
            type: "citation",
            issue: "Factual claim without citation",
            semantic: false
          });
        }
        break;
    }
  });

  return violations;
}

function findMatch(text, keyword) {
  const lower = text.toLowerCase();
  const idx = lower.indexOf(keyword.toLowerCase());
  if (idx >= 0) return text.substring(idx, idx + keyword.length);
  return keyword;
}

// Highlight forbidden phrase violations in DOM (Strikethrough)
function highlightViolations(element, violations, usedMoss) {
  violations.filter(v => v.type !== 'length').forEach(v => {
    if (v.matchedText) {
      try {
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
        let node;
        while (node = walker.nextNode()) {
          const nodeText = node.textContent;
          const idx = nodeText.toLowerCase().indexOf(v.matchedText.toLowerCase());
          if (idx >= 0) {
            const range = document.createRange();
            range.setStart(node, idx);
            range.setEnd(node, idx + v.matchedText.length);

            const highlight = document.createElement('span');
            highlight.className = 'codentia-violation' + (usedMoss ? ' codentia-semantic' : '');
            highlight.style.cssText = 'text-decoration:line-through;background:rgba(255,107,107,0.15);color:#D64545;padding:1px 4px;border-radius:3px;';
            const modeLabel = usedMoss ? '🧠 Moss semantic' : '🔍 Keyword match';
            highlight.title = `Codentia [${modeLabel}]: "${v.rule}" — violation caught`;
            highlight.textContent = range.toString();

            range.deleteContents();
            range.insertNode(highlight);
            break;
          }
        }
      } catch (e) {}
    }
  });
}

function highlightContradiction(element, contradictionClaim) {
  try {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
    let node;
    while (node = walker.nextNode()) {
      if (node.textContent.includes(contradictionClaim.sentence.substring(0, 15))) {
        const span = document.createElement('span');
        span.className = 'codentia-violation codentia-contradiction';
        span.style.cssText = 'text-decoration:line-through;background:rgba(255,0,0,0.2);color:#B71C1C;padding:1px 4px;border-radius:3px;';
        span.title = `🔴 Codentia Truth Layer: Contradiction found against Knowledge Base source (${contradictionClaim.source || 'KB'})`;
        span.textContent = node.textContent;
        node.parentNode.replaceChild(span, node);
        break;
      }
    }
  } catch(e) {}
}

// Feed results into EXISTING compliance badge cleanly positioned at the BOTTOM of the response
function showComplianceBadge(element, violations, usedMoss, latencyMs, truthData) {
  if (element.children.length > 25) return;
  if (element.querySelector('.codentia-badge') || element.closest('.codentia-badge-added')) return;
  element.classList.add('codentia-badge-added');

  const badge = document.createElement('div');
  badge.className = 'codentia-badge';

  const violationCount = violations.length;
  const score = Math.max(0, Math.min(100, Math.round(100 - (violationCount * 15))));
  const modeLabel = usedMoss ? '🧠 Moss semantic' : '🔍 Keyword';
  const latencyLabel = latencyMs ? ` · ${latencyMs}ms` : '';
  const truthLabel = (truthData && truthData.totalClaims > 0) ? ` · Truth: ${truthData.truthScore}%` : '';

  const iconUrl = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL ? chrome.runtime.getURL('icons/icon48.png') : 'icons/icon48.png';

  badge.innerHTML = `
    <div class="codentia-badge-inner ${score < 70 ? 'low-score' : ''}">
      <span class="codentia-badge-icon"><img src="${iconUrl}" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;object-fit:contain;"></span>
      <span class="codentia-badge-score">Compliance: ${score}%</span>
      <span class="codentia-badge-detail">${violationCount} violation${violationCount > 1 ? 's' : ''} · ${modeLabel}${latencyLabel}${truthLabel}</span>
    </div>
  `;

  element.style.position = 'relative';
  element.style.paddingBottom = element.style.paddingBottom || '8px';
  element.appendChild(badge);
}

function showCleanBadge(element, usedMoss, truthData) {
  if (element.children.length > 25) return;
  if (element.querySelector('.codentia-badge') || element.closest('.codentia-badge-added')) return;
  element.classList.add('codentia-badge-added');

  const badge = document.createElement('div');
  badge.className = 'codentia-badge';
  const modeLabel = usedMoss ? '🧠 Moss semantic' : '🔍 Keyword';
  const truthLabel = (truthData && truthData.totalClaims > 0) ? ` · Truth: ${truthData.truthScore}% (🟢 Verified)` : '';
  const iconUrl = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL ? chrome.runtime.getURL('icons/icon48.png') : 'icons/icon48.png';

  badge.innerHTML = `
    <div class="codentia-badge-inner">
      <span class="codentia-badge-icon"><img src="${iconUrl}" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;object-fit:contain;"></span>
      <span class="codentia-badge-score">Compliance: 100%</span>
      <span class="codentia-badge-detail">All rules satisfied · ${modeLabel}${truthLabel}</span>
    </div>
  `;

  element.style.position = 'relative';
  element.style.paddingBottom = element.style.paddingBottom || '8px';
  element.appendChild(badge);
}

init();
