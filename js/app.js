/**
 * ByteHackr Tools - Main Application
 * A client-side security toolkit for hackers and pentesters
 */

// ============================================================================
// INITIALIZATION & NAVIGATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initMatrixBackground();
    initNavigation();
    initHashTool();
    initJWTTool();
    initRegexTool();
    initJSONTool();
    initHexTool();
    initChecksumTool();
    updateDBCount();
});

// Matrix Rain Background
function initMatrixBackground() {
    const canvas = document.getElementById('matrix-bg');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);
    
    function draw() {
        ctx.fillStyle = 'rgba(10, 10, 15, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#00ff88';
        ctx.font = fontSize + 'px JetBrains Mono';
        
        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    setInterval(draw, 50);
    
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// Navigation
function initNavigation() {
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    
    navToggle?.addEventListener('click', () => {
        navMenu.classList.toggle('show');
    });
    
    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.nav') && navMenu.classList.contains('show')) {
            navMenu.classList.remove('show');
        }
    });
}

function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show target section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
    }
    
    // Update nav active state
    document.querySelectorAll('.nav-menu a').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-section') === sectionId) {
            link.classList.add('active');
        }
    });
    
    // Close mobile menu
    document.querySelector('.nav-menu')?.classList.remove('show');
    
    // Scroll to top
    window.scrollTo(0, 0);
}

// ============================================================================
// HASHING & ENCODING TOOL
// ============================================================================

function initHashTool() {
    const dropZone = document.getElementById('hash-drop-zone');
    const fileInput = document.getElementById('hash-file-input');
    
    if (!dropZone || !fileInput) return;
    
    // Click to browse
    dropZone.addEventListener('click', () => fileInput.click());
    
    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) hashFile(file);
    });
    
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) hashFile(file);
    });
    
    // Auto-hash on input
    document.getElementById('hash-input')?.addEventListener('input', debounce(computeAllHashes, 300));
}

function switchHashTab(tab) {
    document.querySelectorAll('#hash .tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('#hash .tab-content').forEach(c => c.classList.remove('active'));
    
    document.querySelector(`#hash .tab:nth-child(${tab === 'text' ? 1 : 2})`)?.classList.add('active');
    document.getElementById(`hash-${tab}-tab`)?.classList.add('active');
}

async function computeHash(algorithm) {
    const input = document.getElementById('hash-input').value;
    const output = document.getElementById('hash-output');
    
    if (!input) {
        output.value = 'Please enter some text to hash';
        return;
    }
    
    try {
        let hash;
        if (algorithm === 'MD5') {
            hash = MD5.hash(input);
        } else {
            const encoder = new TextEncoder();
            const data = encoder.encode(input);
            const hashBuffer = await crypto.subtle.digest(algorithm, data);
            hash = arrayBufferToHex(hashBuffer);
        }
        output.value = hash;
    } catch (error) {
        output.value = 'Error computing hash: ' + error.message;
    }
}

async function computeAllHashes() {
    const input = document.getElementById('hash-input').value;
    if (!input) {
        document.getElementById('all-hashes').style.display = 'none';
        return;
    }
    
    document.getElementById('all-hashes').style.display = 'block';
    
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    
    // MD5
    document.getElementById('all-md5').textContent = MD5.hash(input);
    
    // SHA-1
    const sha1Buffer = await crypto.subtle.digest('SHA-1', data);
    document.getElementById('all-sha1').textContent = arrayBufferToHex(sha1Buffer);
    
    // SHA-256
    const sha256Buffer = await crypto.subtle.digest('SHA-256', data);
    document.getElementById('all-sha256').textContent = arrayBufferToHex(sha256Buffer);
    
    // SHA-512
    const sha512Buffer = await crypto.subtle.digest('SHA-512', data);
    document.getElementById('all-sha512').textContent = arrayBufferToHex(sha512Buffer);
}

async function computeHMAC(algorithm) {
    const input = document.getElementById('hash-input').value;
    const key = document.getElementById('hmac-key').value;
    const output = document.getElementById('hash-output');
    
    if (!input) {
        output.value = 'Please enter some text';
        return;
    }
    
    if (!key) {
        output.value = 'Please enter a secret key for HMAC';
        return;
    }
    
    try {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(key);
        const messageData = encoder.encode(input);
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: algorithm },
            false,
            ['sign']
        );
        
        const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
        output.value = arrayBufferToHex(signature);
    } catch (error) {
        output.value = 'Error computing HMAC: ' + error.message;
    }
}

function encodeBase64() {
    const input = document.getElementById('hash-input').value;
    const output = document.getElementById('hash-output');
    
    try {
        output.value = btoa(unescape(encodeURIComponent(input)));
    } catch (error) {
        output.value = 'Error encoding: ' + error.message;
    }
}

function decodeBase64() {
    const input = document.getElementById('hash-input').value;
    const output = document.getElementById('hash-output');
    
    try {
        output.value = decodeURIComponent(escape(atob(input)));
    } catch (error) {
        output.value = 'Error decoding: Invalid Base64 string';
    }
}

function encodeHex() {
    const input = document.getElementById('hash-input').value;
    const output = document.getElementById('hash-output');
    
    const hex = Array.from(input)
        .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');
    output.value = hex;
}

function decodeHex() {
    const input = document.getElementById('hash-input').value.replace(/\s/g, '');
    const output = document.getElementById('hash-output');
    
    try {
        const decoded = input.match(/.{1,2}/g)
            ?.map(byte => String.fromCharCode(parseInt(byte, 16)))
            .join('') || '';
        output.value = decoded;
    } catch (error) {
        output.value = 'Error decoding: Invalid hex string';
    }
}

function encodeURL() {
    const input = document.getElementById('hash-input').value;
    document.getElementById('hash-output').value = encodeURIComponent(input);
}

function decodeURL() {
    const input = document.getElementById('hash-input').value;
    try {
        document.getElementById('hash-output').value = decodeURIComponent(input);
    } catch (error) {
        document.getElementById('hash-output').value = 'Error decoding: Invalid URL encoded string';
    }
}

async function hashFile(file) {
    const resultsDiv = document.getElementById('file-hash-results');
    const progressBar = document.getElementById('hash-progress');
    
    resultsDiv.style.display = 'block';
    progressBar.style.display = 'block';
    
    document.getElementById('file-name').textContent = file.name;
    document.getElementById('file-size').textContent = formatFileSize(file.size);
    
    // Reset results
    ['md5', 'sha1', 'sha256', 'sha512'].forEach(algo => {
        document.getElementById(`file-${algo}`).textContent = 'Computing...';
    });
    
    const arrayBuffer = await file.arrayBuffer();
    const progressFill = progressBar.querySelector('.progress-fill');
    
    // MD5
    progressFill.style.width = '25%';
    document.getElementById('file-md5').textContent = MD5.hashArrayBuffer(arrayBuffer);
    
    // SHA-1
    progressFill.style.width = '50%';
    const sha1Hash = await crypto.subtle.digest('SHA-1', arrayBuffer);
    document.getElementById('file-sha1').textContent = arrayBufferToHex(sha1Hash);
    
    // SHA-256
    progressFill.style.width = '75%';
    const sha256Hash = await crypto.subtle.digest('SHA-256', arrayBuffer);
    document.getElementById('file-sha256').textContent = arrayBufferToHex(sha256Hash);
    
    // SHA-512
    progressFill.style.width = '100%';
    const sha512Hash = await crypto.subtle.digest('SHA-512', arrayBuffer);
    document.getElementById('file-sha512').textContent = arrayBufferToHex(sha512Hash);
    
    setTimeout(() => {
        progressBar.style.display = 'none';
    }, 500);
}

// ============================================================================
// JWT INSPECTOR TOOL
// ============================================================================

function initJWTTool() {
    document.getElementById('jwt-input')?.addEventListener('input', debounce(decodeJWT, 300));
}

function decodeJWT() {
    const token = document.getElementById('jwt-input').value.trim();
    const resultDiv = document.getElementById('jwt-result');
    
    if (!token) {
        resultDiv.style.display = 'none';
        return;
    }
    
    const parts = token.split('.');
    
    if (parts.length !== 3) {
        resultDiv.style.display = 'none';
        alert('Invalid JWT format. Expected 3 parts separated by dots.');
        return;
    }
    
    try {
        // Decode header
        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        document.getElementById('jwt-header').textContent = JSON.stringify(header, null, 2);
        
        // Decode payload
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        document.getElementById('jwt-payload').textContent = JSON.stringify(payload, null, 2);
        
        // Display signature
        document.getElementById('jwt-signature').textContent = parts[2];
        
        // Analyze claims
        displayJWTClaims(payload);
        
        // Set algorithm in verify select
        if (header.alg) {
            const algoSelect = document.getElementById('jwt-algo');
            const option = Array.from(algoSelect.options).find(o => o.value === header.alg);
            if (option) algoSelect.value = header.alg;
        }
        
        resultDiv.style.display = 'block';
    } catch (error) {
        resultDiv.style.display = 'none';
        alert('Error decoding JWT: ' + error.message);
    }
}

function displayJWTClaims(payload) {
    const claimsDiv = document.getElementById('jwt-claims');
    let html = '';
    
    const standardClaims = {
        iss: 'Issuer',
        sub: 'Subject',
        aud: 'Audience',
        exp: 'Expiration',
        nbf: 'Not Before',
        iat: 'Issued At',
        jti: 'JWT ID'
    };
    
    for (const [key, label] of Object.entries(standardClaims)) {
        if (payload[key] !== undefined) {
            let value = payload[key];
            
            // Format timestamps
            if (['exp', 'nbf', 'iat'].includes(key)) {
                const date = new Date(value * 1000);
                const isExpired = key === 'exp' && date < new Date();
                value = `<span class="claim-value ${isExpired ? 'expired' : ''}">${date.toISOString()}</span>`;
                if (isExpired) value += ' <span style="color: var(--accent-danger);">(EXPIRED)</span>';
            } else {
                value = `<span class="claim-value">${value}</span>`;
            }
            
            html += `<p><strong>${label}:</strong> ${value}</p>`;
        }
    }
    
    claimsDiv.innerHTML = html || '<p>No standard claims found</p>';
}

async function verifyJWT() {
    const token = document.getElementById('jwt-input').value.trim();
    const secret = document.getElementById('jwt-secret').value;
    const algorithm = document.getElementById('jwt-algo').value;
    const resultDiv = document.getElementById('jwt-verify-result');
    
    if (!secret) {
        resultDiv.className = 'verify-result invalid';
        resultDiv.textContent = 'Please enter a secret key';
        resultDiv.style.display = 'block';
        return;
    }
    
    const parts = token.split('.');
    if (parts.length !== 3) {
        resultDiv.className = 'verify-result invalid';
        resultDiv.textContent = 'Invalid JWT format';
        resultDiv.style.display = 'block';
        return;
    }
    
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(parts[0] + '.' + parts[1]);
        const keyData = encoder.encode(secret);
        
        const hashAlgo = algorithm.replace('HS', 'SHA-');
        
        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: hashAlgo },
            false,
            ['sign']
        );
        
        const signature = await crypto.subtle.sign('HMAC', key, data);
        const computedSig = base64UrlEncode(new Uint8Array(signature));
        
        // Normalize the original signature
        const originalSig = parts[2].replace(/-/g, '+').replace(/_/g, '/');
        const computedNormalized = computedSig.replace(/-/g, '+').replace(/_/g, '/');
        
        if (originalSig === computedNormalized) {
            resultDiv.className = 'verify-result valid';
            resultDiv.textContent = '✓ Signature verified successfully!';
        } else {
            resultDiv.className = 'verify-result invalid';
            resultDiv.textContent = '✗ Signature verification failed!';
        }
        resultDiv.style.display = 'block';
    } catch (error) {
        resultDiv.className = 'verify-result invalid';
        resultDiv.textContent = 'Error verifying: ' + error.message;
        resultDiv.style.display = 'block';
    }
}

function loadExampleJWT() {
    // This is a valid JWT with secret "secret"
    const exampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MTYyMzkwMjIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    document.getElementById('jwt-input').value = exampleToken;
    decodeJWT();
}

function base64UrlEncode(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ============================================================================
// REGEX TESTER TOOL
// ============================================================================

function initRegexTool() {
    const patternInput = document.getElementById('regex-pattern');
    const flagsInput = document.getElementById('regex-flags');
    const testInput = document.getElementById('regex-test-string');
    const replaceInput = document.getElementById('regex-replace');
    
    const runRegex = debounce(testRegex, 150);
    
    patternInput?.addEventListener('input', runRegex);
    flagsInput?.addEventListener('input', runRegex);
    testInput?.addEventListener('input', runRegex);
    replaceInput?.addEventListener('input', runRegex);
}

function testRegex() {
    const pattern = document.getElementById('regex-pattern').value;
    const flags = document.getElementById('regex-flags').value;
    const testString = document.getElementById('regex-test-string').value;
    const replaceWith = document.getElementById('regex-replace').value;
    
    const matchesDiv = document.getElementById('regex-matches');
    const highlightedDiv = document.getElementById('regex-highlighted');
    const groupsDiv = document.getElementById('regex-groups');
    const matchCount = document.getElementById('match-count');
    const replacePanel = document.getElementById('replace-preview-panel');
    const replacePreview = document.getElementById('regex-replace-preview');
    
    // Reset
    matchesDiv.innerHTML = '';
    highlightedDiv.innerHTML = '';
    groupsDiv.innerHTML = '';
    matchCount.textContent = '0';
    replacePanel.style.display = 'none';
    
    if (!pattern || !testString) {
        highlightedDiv.textContent = testString || 'Enter a pattern and test string...';
        return;
    }
    
    try {
        const regex = new RegExp(pattern, flags);
        const matches = [];
        const groups = [];
        let match;
        
        if (flags.includes('g')) {
            while ((match = regex.exec(testString)) !== null) {
                matches.push({
                    value: match[0],
                    index: match.index,
                    groups: match.slice(1)
                });
                if (match[0].length === 0) regex.lastIndex++;
            }
        } else {
            match = regex.exec(testString);
            if (match) {
                matches.push({
                    value: match[0],
                    index: match.index,
                    groups: match.slice(1)
                });
            }
        }
        
        // Update match count
        matchCount.textContent = matches.length;
        
        // Display matches
        if (matches.length > 0) {
            matchesDiv.innerHTML = matches.map((m, i) => `
                <div class="match-item">
                    <span class="match-index">#${i + 1}</span>
                    <span class="match-value">"${escapeHtml(m.value)}"</span>
                    <span class="match-index">@${m.index}</span>
                </div>
            `).join('');
            
            // Highlight matches
            highlightedDiv.innerHTML = highlightMatches(testString, matches);
            
            // Display groups
            const allGroups = matches.flatMap((m, i) => 
                m.groups.map((g, gi) => ({ matchIndex: i + 1, groupIndex: gi + 1, value: g }))
            ).filter(g => g.value !== undefined);
            
            if (allGroups.length > 0) {
                groupsDiv.innerHTML = allGroups.map(g => `
                    <div class="group-item">
                        <span class="group-name">Match ${g.matchIndex}, Group ${g.groupIndex}</span>
                        <span class="group-value">"${escapeHtml(g.value || '')}"</span>
                    </div>
                `).join('');
            } else {
                groupsDiv.innerHTML = '<p style="color: var(--text-muted);">No capture groups</p>';
            }
            
            // Replace preview
            if (replaceWith) {
                replacePanel.style.display = 'block';
                replacePreview.textContent = testString.replace(regex, replaceWith);
            }
        } else {
            matchesDiv.innerHTML = '<p style="color: var(--text-muted);">No matches found</p>';
            highlightedDiv.textContent = testString;
            groupsDiv.innerHTML = '<p style="color: var(--text-muted);">No groups</p>';
        }
        
    } catch (error) {
        matchesDiv.innerHTML = `<p style="color: var(--accent-danger);">Invalid regex: ${error.message}</p>`;
        highlightedDiv.textContent = testString;
    }
}

function highlightMatches(text, matches) {
    if (matches.length === 0) return escapeHtml(text);
    
    // Sort matches by index (descending) to replace from end to start
    const sortedMatches = [...matches].sort((a, b) => b.index - a.index);
    
    let result = text;
    for (const match of sortedMatches) {
        const before = result.substring(0, match.index);
        const highlighted = `<mark>${escapeHtml(match.value)}</mark>`;
        const after = result.substring(match.index + match.value.length);
        result = before + highlighted + after;
    }
    
    // Escape HTML for non-highlighted parts
    return result.split(/<mark>|<\/mark>/).map((part, i) => 
        i % 2 === 0 ? escapeHtml(part) : `<mark>${part}</mark>`
    ).join('');
}

function toggleCheatsheet() {
    const content = document.getElementById('cheatsheet-content');
    const btn = document.querySelector('.btn-toggle');
    content.classList.toggle('show');
    btn.textContent = content.classList.contains('show') ? '▲' : '▼';
}

// ============================================================================
// JSON/YAML CONVERTER TOOL
// ============================================================================

function initJSONTool() {
    const inputFormat = document.getElementById('input-format');
    const outputFormat = document.getElementById('output-format');
    
    inputFormat?.addEventListener('change', () => {
        if (inputFormat.value === outputFormat.value) {
            outputFormat.value = inputFormat.value === 'json' ? 'yaml' : 'json';
        }
    });
    
    outputFormat?.addEventListener('change', () => {
        if (inputFormat.value === outputFormat.value) {
            inputFormat.value = outputFormat.value === 'json' ? 'yaml' : 'json';
        }
    });
    
    document.getElementById('json-input')?.addEventListener('input', debounce(() => {
        clearError();
        validateInput();
    }, 300));
}

function convertData() {
    const input = document.getElementById('json-input').value.trim();
    const inputFormat = document.getElementById('input-format').value;
    const outputFormat = document.getElementById('output-format').value;
    const output = document.getElementById('json-output');
    const errorDiv = document.getElementById('input-error');
    
    if (!input) {
        output.value = '';
        return;
    }
    
    try {
        let data;
        
        // Parse input
        if (inputFormat === 'json') {
            data = JSON.parse(input);
        } else {
            data = jsyaml.load(input);
        }
        
        // Convert to output format
        if (outputFormat === 'json') {
            output.value = JSON.stringify(data, null, 2);
        } else {
            output.value = jsyaml.dump(data, { indent: 2, lineWidth: -1 });
        }
        
        errorDiv.textContent = '';
    } catch (error) {
        errorDiv.textContent = 'Error: ' + error.message;
        output.value = '';
    }
}

function prettifyInput() {
    const input = document.getElementById('json-input');
    const format = document.getElementById('input-format').value;
    const errorDiv = document.getElementById('input-error');
    
    try {
        let data;
        if (format === 'json') {
            data = JSON.parse(input.value);
            input.value = JSON.stringify(data, null, 2);
        } else {
            data = jsyaml.load(input.value);
            input.value = jsyaml.dump(data, { indent: 2, lineWidth: -1 });
        }
        errorDiv.textContent = '';
    } catch (error) {
        errorDiv.textContent = 'Error: ' + error.message;
    }
}

function minifyInput() {
    const input = document.getElementById('json-input');
    const format = document.getElementById('input-format').value;
    const errorDiv = document.getElementById('input-error');
    
    try {
        let data;
        if (format === 'json') {
            data = JSON.parse(input.value);
            input.value = JSON.stringify(data);
        } else {
            data = jsyaml.load(input.value);
            input.value = jsyaml.dump(data, { flowLevel: 0 }).trim();
        }
        errorDiv.textContent = '';
    } catch (error) {
        errorDiv.textContent = 'Error: ' + error.message;
    }
}

function clearInput() {
    document.getElementById('json-input').value = '';
    document.getElementById('json-output').value = '';
    document.getElementById('input-error').textContent = '';
}

function swapFormats() {
    const inputFormat = document.getElementById('input-format');
    const outputFormat = document.getElementById('output-format');
    const inputText = document.getElementById('json-input');
    const outputText = document.getElementById('json-output');
    
    // Swap formats
    const tempFormat = inputFormat.value;
    inputFormat.value = outputFormat.value;
    outputFormat.value = tempFormat;
    
    // Swap content if output has content
    if (outputText.value) {
        inputText.value = outputText.value;
        outputText.value = '';
    }
}

function validateInput() {
    const input = document.getElementById('json-input').value.trim();
    const format = document.getElementById('input-format').value;
    const errorDiv = document.getElementById('input-error');
    
    if (!input) return;
    
    try {
        if (format === 'json') {
            JSON.parse(input);
        } else {
            jsyaml.load(input);
        }
        errorDiv.textContent = '';
    } catch (error) {
        errorDiv.textContent = 'Syntax error: ' + error.message;
    }
}

function clearError() {
    document.getElementById('input-error').textContent = '';
}

function navigatePath() {
    const input = document.getElementById('json-input').value.trim();
    const path = document.getElementById('json-path').value.trim();
    const result = document.getElementById('path-result');
    const format = document.getElementById('input-format').value;
    
    if (!input || !path) {
        result.textContent = 'Enter a valid path (e.g., data.users[0].name)';
        return;
    }
    
    try {
        let data;
        if (format === 'json') {
            data = JSON.parse(input);
        } else {
            data = jsyaml.load(input);
        }
        
        // Navigate the path
        const value = getNestedValue(data, path);
        
        if (value === undefined) {
            result.textContent = 'Path not found';
        } else if (typeof value === 'object') {
            result.textContent = JSON.stringify(value, null, 2);
        } else {
            result.textContent = String(value);
        }
    } catch (error) {
        result.textContent = 'Error: ' + error.message;
    }
}

function getNestedValue(obj, path) {
    const keys = path.replace(/\[(\d+)\]/g, '.$1').split('.');
    let current = obj;
    
    for (const key of keys) {
        if (current === null || current === undefined) return undefined;
        current = current[key];
    }
    
    return current;
}

function validateSchema() {
    const input = document.getElementById('json-input').value.trim();
    const schemaInput = document.getElementById('json-schema').value.trim();
    const resultDiv = document.getElementById('schema-result');
    const format = document.getElementById('input-format').value;
    
    if (!input || !schemaInput) {
        resultDiv.textContent = 'Please provide both data and schema';
        resultDiv.className = 'schema-result';
        return;
    }
    
    try {
        let data, schema;
        
        if (format === 'json') {
            data = JSON.parse(input);
        } else {
            data = jsyaml.load(input);
        }
        
        schema = JSON.parse(schemaInput);
        
        // Simple schema validation
        const errors = validateAgainstSchema(data, schema);
        
        if (errors.length === 0) {
            resultDiv.innerHTML = '✓ Data is valid against the schema';
            resultDiv.className = 'schema-result valid';
        } else {
            resultDiv.innerHTML = '✗ Validation errors:<br>' + errors.map(e => '• ' + e).join('<br>');
            resultDiv.className = 'schema-result invalid';
        }
    } catch (error) {
        resultDiv.textContent = 'Error: ' + error.message;
        resultDiv.className = 'schema-result invalid';
    }
}

function validateAgainstSchema(data, schema, path = 'root') {
    const errors = [];
    
    // Type validation
    if (schema.type) {
        const actualType = Array.isArray(data) ? 'array' : typeof data;
        if (schema.type !== actualType && !(schema.type === 'integer' && Number.isInteger(data))) {
            errors.push(`${path}: Expected ${schema.type}, got ${actualType}`);
        }
    }
    
    // Required properties
    if (schema.required && typeof data === 'object' && !Array.isArray(data)) {
        for (const prop of schema.required) {
            if (!(prop in data)) {
                errors.push(`${path}: Missing required property "${prop}"`);
            }
        }
    }
    
    // Properties validation
    if (schema.properties && typeof data === 'object' && !Array.isArray(data)) {
        for (const [key, propSchema] of Object.entries(schema.properties)) {
            if (key in data) {
                errors.push(...validateAgainstSchema(data[key], propSchema, `${path}.${key}`));
            }
        }
    }
    
    // Array items validation
    if (schema.items && Array.isArray(data)) {
        data.forEach((item, i) => {
            errors.push(...validateAgainstSchema(item, schema.items, `${path}[${i}]`));
        });
    }
    
    // Min/max validation
    if (typeof data === 'number') {
        if (schema.minimum !== undefined && data < schema.minimum) {
            errors.push(`${path}: Value ${data} is less than minimum ${schema.minimum}`);
        }
        if (schema.maximum !== undefined && data > schema.maximum) {
            errors.push(`${path}: Value ${data} is greater than maximum ${schema.maximum}`);
        }
    }
    
    // String length validation
    if (typeof data === 'string') {
        if (schema.minLength !== undefined && data.length < schema.minLength) {
            errors.push(`${path}: String length ${data.length} is less than minLength ${schema.minLength}`);
        }
        if (schema.maxLength !== undefined && data.length > schema.maxLength) {
            errors.push(`${path}: String length ${data.length} is greater than maxLength ${schema.maxLength}`);
        }
        if (schema.pattern && !new RegExp(schema.pattern).test(data)) {
            errors.push(`${path}: String does not match pattern "${schema.pattern}"`);
        }
    }
    
    // Enum validation
    if (schema.enum && !schema.enum.includes(data)) {
        errors.push(`${path}: Value must be one of [${schema.enum.join(', ')}]`);
    }
    
    return errors;
}

function downloadOutput() {
    const output = document.getElementById('json-output').value;
    const format = document.getElementById('output-format').value;
    
    if (!output) return;
    
    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `output.${format}`;
    a.click();
    URL.revokeObjectURL(url);
}

// ============================================================================
// HEX VIEWER TOOL
// ============================================================================

let hexData = null;
let hexInputType = 'text';

function initHexTool() {
    const dropZone = document.getElementById('hex-drop-zone');
    const fileInput = document.getElementById('hex-file-input');
    
    if (!dropZone || !fileInput) return;
    
    dropZone.addEventListener('click', () => fileInput.click());
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) loadHexFile(file);
    });
    
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) loadHexFile(file);
    });
}

function switchHexTab(tab) {
    document.querySelectorAll('#hex .tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('#hex .tab-content').forEach(c => c.classList.remove('active'));
    
    document.querySelector(`#hex .tab:nth-child(${tab === 'paste' ? 1 : 2})`)?.classList.add('active');
    document.getElementById(`hex-${tab}-tab`)?.classList.add('active');
}

function setHexInputType(type) {
    hexInputType = type;
    document.querySelectorAll('#hex-paste-tab .btn-group .btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
}

function analyzeHex() {
    const input = document.getElementById('hex-input').value;
    
    if (!input) return;
    
    let bytes;
    
    try {
        if (hexInputType === 'text') {
            bytes = new TextEncoder().encode(input);
        } else if (hexInputType === 'hex') {
            const hexStr = input.replace(/\s/g, '').replace(/0x/gi, '');
            bytes = new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        } else if (hexInputType === 'base64') {
            const binary = atob(input.replace(/\s/g, ''));
            bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
        }
        
        hexData = bytes;
        displayHexView();
    } catch (error) {
        alert('Error parsing input: ' + error.message);
    }
}

async function loadHexFile(file) {
    try {
        const arrayBuffer = await file.arrayBuffer();
        hexData = new Uint8Array(arrayBuffer);
        displayHexView();
    } catch (error) {
        alert('Error loading file: ' + error.message);
    }
}

function displayHexView() {
    const resultsDiv = document.getElementById('hex-results');
    resultsDiv.style.display = 'block';
    
    document.getElementById('hex-size').textContent = formatFileSize(hexData.length);
    
    // Detect signature
    const signature = detectSignature(hexData);
    const sigInfo = document.getElementById('signature-info');
    const sigBadge = document.getElementById('hex-signature');
    
    if (signature) {
        sigInfo.style.display = 'flex';
        sigBadge.textContent = signature;
    } else {
        sigInfo.style.display = 'none';
    }
    
    updateHexView();
}

function updateHexView() {
    if (!hexData) return;
    
    const bytesPerRow = parseInt(document.getElementById('bytes-per-row').value);
    const offset = parseInt(document.getElementById('hex-offset').value) || 0;
    const limit = parseInt(document.getElementById('hex-limit').value) || 512;
    
    const hexView = document.getElementById('hex-view');
    let html = '';
    
    const endOffset = Math.min(offset + limit, hexData.length);
    
    for (let i = offset; i < endOffset; i += bytesPerRow) {
        const rowBytes = hexData.slice(i, Math.min(i + bytesPerRow, hexData.length));
        
        // Offset column
        const offsetHex = i.toString(16).toUpperCase().padStart(8, '0');
        
        // Hex bytes
        const hexBytes = Array.from(rowBytes).map(byte => {
            const hex = byte.toString(16).toUpperCase().padStart(2, '0');
            const cls = byte === 0 ? 'null' : (byte >= 32 && byte < 127 ? 'printable' : '');
            return `<span class="hex-byte ${cls}">${hex}</span>`;
        }).join('');
        
        // ASCII representation
        const ascii = Array.from(rowBytes).map(byte => {
            if (byte >= 32 && byte < 127) {
                return escapeHtml(String.fromCharCode(byte));
            }
            return '<span class="non-printable">.</span>';
        }).join('');
        
        html += `
            <div class="hex-row">
                <span class="hex-offset">${offsetHex}</span>
                <span class="hex-bytes">${hexBytes}</span>
                <span class="hex-ascii">${ascii}</span>
            </div>
        `;
    }
    
    hexView.innerHTML = html;
}

function detectSignature(bytes) {
    if (bytes.length < 4) return null;
    
    const signatures = [
        { sig: [0x4D, 0x5A], name: 'PE/MZ (Windows Executable)' },
        { sig: [0x7F, 0x45, 0x4C, 0x46], name: 'ELF (Linux Executable)' },
        { sig: [0x25, 0x50, 0x44, 0x46], name: 'PDF Document' },
        { sig: [0x50, 0x4B, 0x03, 0x04], name: 'ZIP Archive' },
        { sig: [0x50, 0x4B, 0x05, 0x06], name: 'ZIP Archive (empty)' },
        { sig: [0x52, 0x61, 0x72, 0x21], name: 'RAR Archive' },
        { sig: [0x1F, 0x8B, 0x08], name: 'GZIP Archive' },
        { sig: [0x42, 0x5A, 0x68], name: 'BZIP2 Archive' },
        { sig: [0x89, 0x50, 0x4E, 0x47], name: 'PNG Image' },
        { sig: [0xFF, 0xD8, 0xFF], name: 'JPEG Image' },
        { sig: [0x47, 0x49, 0x46, 0x38], name: 'GIF Image' },
        { sig: [0x42, 0x4D], name: 'BMP Image' },
        { sig: [0x49, 0x44, 0x33], name: 'MP3 Audio (ID3)' },
        { sig: [0xFF, 0xFB], name: 'MP3 Audio' },
        { sig: [0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70], name: 'MP4 Video' },
        { sig: [0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], name: 'MP4 Video' },
        { sig: [0x66, 0x74, 0x79, 0x70], name: 'MP4/MOV Video', offset: 4 },
        { sig: [0x52, 0x49, 0x46, 0x46], name: 'RIFF (AVI/WAV)' },
        { sig: [0xCA, 0xFE, 0xBA, 0xBE], name: 'Java Class/Mach-O Fat' },
        { sig: [0xCE, 0xFA, 0xED, 0xFE], name: 'Mach-O (32-bit)' },
        { sig: [0xCF, 0xFA, 0xED, 0xFE], name: 'Mach-O (64-bit)' },
        { sig: [0xD0, 0xCF, 0x11, 0xE0], name: 'MS Office (OLE)' },
        { sig: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], name: 'SQLite Database' },
        { sig: [0x3C, 0x3F, 0x78, 0x6D, 0x6C], name: 'XML Document' },
        { sig: [0x3C, 0x21, 0x44, 0x4F, 0x43], name: 'HTML Document' },
        { sig: [0x7B, 0x22], name: 'JSON (object)' },
        { sig: [0x5B], name: 'JSON (array)' },
    ];
    
    for (const { sig, name, offset = 0 } of signatures) {
        if (bytes.length < offset + sig.length) continue;
        
        let match = true;
        for (let i = 0; i < sig.length; i++) {
            if (bytes[offset + i] !== sig[i]) {
                match = false;
                break;
            }
        }
        if (match) return name;
    }
    
    return null;
}

// ============================================================================
// CHECKSUM LOOKUP TOOL
// ============================================================================

// Local database of known-good hashes (common tools and system files)
const KNOWN_HASHES = {
    // Common utilities SHA-256
    'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592': { name: 'Empty file', type: 'system' },
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': { name: 'Empty file (SHA-256)', type: 'system' },
    
    // Add more known hashes here
    // Format: 'hash': { name: 'File/Tool name', type: 'category', version: 'x.x.x' }
};

let compareHash1 = null;
let compareHash2 = null;

function initChecksumTool() {
    // Main checksum drop zone
    const dropZone = document.getElementById('checksum-drop-zone');
    const fileInput = document.getElementById('checksum-file-input');
    
    if (dropZone && fileInput) {
        dropZone.addEventListener('click', () => fileInput.click());
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            if (file) calculateChecksums(file);
        });
        
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) calculateChecksums(file);
        });
    }
    
    // Compare drop zones
    setupCompareDropZone('compare-drop-1', 'compare-file-1', 1);
    setupCompareDropZone('compare-drop-2', 'compare-file-2', 2);
    
    // VirusTotal toggle
    document.getElementById('lookup-vt')?.addEventListener('change', (e) => {
        document.getElementById('vt-key-input').style.display = e.target.checked ? 'block' : 'none';
    });
    
    // Expected checksum verification
    document.getElementById('expected-checksum')?.addEventListener('input', debounce(verifyExpectedChecksum, 300));
}

function setupCompareDropZone(dropId, inputId, num) {
    const dropZone = document.getElementById(dropId);
    const fileInput = document.getElementById(inputId);
    
    if (!dropZone || !fileInput) return;
    
    dropZone.addEventListener('click', () => fileInput.click());
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) await calculateCompareHash(file, num);
    });
    
    fileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) await calculateCompareHash(file, num);
    });
}

function switchChecksumTab(tab) {
    document.querySelectorAll('#checksum .tabs .tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('#checksum .tab-content').forEach(c => c.classList.remove('active'));
    
    const tabIndex = { verify: 1, lookup: 2, compare: 3 }[tab];
    document.querySelector(`#checksum .tabs .tab:nth-child(${tabIndex})`)?.classList.add('active');
    document.getElementById(`checksum-${tab}-tab`)?.classList.add('active');
}

async function calculateChecksums(file) {
    const resultsDiv = document.getElementById('checksum-results');
    resultsDiv.style.display = 'block';
    
    ['md5', 'sha1', 'sha256', 'sha512'].forEach(algo => {
        document.getElementById(`checksum-${algo}`).textContent = 'Computing...';
        document.getElementById(`verify-${algo}`).textContent = '';
        document.getElementById(`verify-${algo}`).className = 'verify-badge';
    });
    
    const arrayBuffer = await file.arrayBuffer();
    
    // MD5
    document.getElementById('checksum-md5').textContent = MD5.hashArrayBuffer(arrayBuffer);
    
    // SHA-1
    const sha1Hash = await crypto.subtle.digest('SHA-1', arrayBuffer);
    document.getElementById('checksum-sha1').textContent = arrayBufferToHex(sha1Hash);
    
    // SHA-256
    const sha256Hash = await crypto.subtle.digest('SHA-256', arrayBuffer);
    document.getElementById('checksum-sha256').textContent = arrayBufferToHex(sha256Hash);
    
    // SHA-512
    const sha512Hash = await crypto.subtle.digest('SHA-512', arrayBuffer);
    document.getElementById('checksum-sha512').textContent = arrayBufferToHex(sha512Hash);
    
    // Verify against expected
    verifyExpectedChecksum();
}

function verifyExpectedChecksum() {
    const expected = document.getElementById('expected-checksum').value.toLowerCase().trim();
    
    if (!expected) {
        ['md5', 'sha1', 'sha256', 'sha512'].forEach(algo => {
            document.getElementById(`verify-${algo}`).textContent = '';
            document.getElementById(`verify-${algo}`).className = 'verify-badge';
        });
        return;
    }
    
    ['md5', 'sha1', 'sha256', 'sha512'].forEach(algo => {
        const computed = document.getElementById(`checksum-${algo}`).textContent.toLowerCase();
        const badge = document.getElementById(`verify-${algo}`);
        
        if (computed === 'Computing...' || computed === '-') return;
        
        if (computed === expected) {
            badge.textContent = '✓ MATCH';
            badge.className = 'verify-badge match';
        } else {
            badge.textContent = '';
            badge.className = 'verify-badge';
        }
    });
}

async function calculateCompareHash(file, num) {
    const hashDiv = document.getElementById(`compare-hash-${num}`);
    hashDiv.textContent = 'Computing...';
    
    const arrayBuffer = await file.arrayBuffer();
    const sha256Hash = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashHex = arrayBufferToHex(sha256Hash);
    
    hashDiv.textContent = hashHex;
    
    if (num === 1) {
        compareHash1 = hashHex;
    } else {
        compareHash2 = hashHex;
    }
    
    updateCompareResult();
}

function updateCompareResult() {
    const statusDiv = document.getElementById('compare-status');
    const statusIcon = statusDiv.querySelector('.status-icon');
    const statusText = statusDiv.querySelector('.status-text');
    
    if (!compareHash1 || !compareHash2) {
        statusDiv.className = 'compare-status';
        statusIcon.textContent = '?';
        statusText.textContent = 'Drop two files to compare';
        return;
    }
    
    if (compareHash1 === compareHash2) {
        statusDiv.className = 'compare-status match';
        statusIcon.textContent = '✓';
        statusText.textContent = 'Files are identical';
    } else {
        statusDiv.className = 'compare-status no-match';
        statusIcon.textContent = '✗';
        statusText.textContent = 'Files are different';
    }
}

async function lookupHash() {
    const hash = document.getElementById('lookup-hash').value.trim().toLowerCase();
    const useLocal = document.getElementById('lookup-local').checked;
    const useVT = document.getElementById('lookup-vt').checked;
    const resultsDiv = document.getElementById('lookup-results');
    const contentDiv = document.getElementById('lookup-content');
    
    if (!hash) {
        alert('Please enter a hash to lookup');
        return;
    }
    
    resultsDiv.style.display = 'block';
    contentDiv.innerHTML = '<p>Looking up...</p>';
    
    let results = [];
    
    // Local lookup
    if (useLocal) {
        const localResult = KNOWN_HASHES[hash];
        if (localResult) {
            results.push(`
                <div class="lookup-item success">
                    <h5>📦 Local Database</h5>
                    <p><strong>File:</strong> ${localResult.name}</p>
                    <p><strong>Type:</strong> ${localResult.type}</p>
                    ${localResult.version ? `<p><strong>Version:</strong> ${localResult.version}</p>` : ''}
                    <p class="status-good">✓ Known good file</p>
                </div>
            `);
        } else {
            results.push(`
                <div class="lookup-item">
                    <h5>📦 Local Database</h5>
                    <p>Hash not found in local database</p>
                </div>
            `);
        }
    }
    
    // VirusTotal lookup
    if (useVT) {
        const apiKey = document.getElementById('vt-api-key').value.trim();
        if (!apiKey) {
            results.push(`
                <div class="lookup-item warning">
                    <h5>🔍 VirusTotal</h5>
                    <p>API key required for VirusTotal lookups</p>
                </div>
            `);
        } else {
            try {
                const vtResult = await lookupVirusTotal(hash, apiKey);
                results.push(vtResult);
            } catch (error) {
                results.push(`
                    <div class="lookup-item error">
                        <h5>🔍 VirusTotal</h5>
                        <p>Error: ${error.message}</p>
                    </div>
                `);
            }
        }
    }
    
    contentDiv.innerHTML = results.join('') || '<p>No lookup sources selected</p>';
}

async function lookupVirusTotal(hash, apiKey) {
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: {
                'x-apikey': apiKey
            }
        });
        
        if (response.status === 404) {
            return `
                <div class="lookup-item">
                    <h5>🔍 VirusTotal</h5>
                    <p>Hash not found in VirusTotal database</p>
                </div>
            `;
        }
        
        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }
        
        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;
        const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
        
        const isMalicious = stats.malicious > 0;
        
        return `
            <div class="lookup-item ${isMalicious ? 'error' : 'success'}">
                <h5>🔍 VirusTotal</h5>
                <p><strong>Detection:</strong> ${stats.malicious}/${total} engines flagged as malicious</p>
                <p><strong>Suspicious:</strong> ${stats.suspicious}</p>
                <p><strong>Harmless:</strong> ${stats.harmless}</p>
                <p class="${isMalicious ? 'status-bad' : 'status-good'}">
                    ${isMalicious ? '⚠️ Potentially malicious file!' : '✓ No threats detected'}
                </p>
            </div>
        `;
    } catch (error) {
        throw error;
    }
}

function updateDBCount() {
    const count = Object.keys(KNOWN_HASHES).length;
    const countEl = document.getElementById('db-count');
    if (countEl) countEl.textContent = count;
}

function showHashDB() {
    const entries = Object.entries(KNOWN_HASHES);
    let html = '<h3>Known Hash Database</h3><table class="hash-db-table">';
    html += '<tr><th>Hash (truncated)</th><th>Name</th><th>Type</th></tr>';
    
    for (const [hash, info] of entries) {
        html += `<tr>
            <td><code>${hash.substring(0, 16)}...</code></td>
            <td>${info.name}</td>
            <td>${info.type}</td>
        </tr>`;
    }
    
    html += '</table>';
    
    const popup = window.open('', 'Hash Database', 'width=600,height=400');
    popup.document.write(`
        <html>
        <head>
            <title>Hash Database</title>
            <style>
                body { font-family: monospace; background: #0a0a0f; color: #e8e8f0; padding: 20px; }
                h3 { color: #00ff88; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { padding: 8px; border: 1px solid #333; text-align: left; }
                th { background: #1a1a25; color: #00ff88; }
                code { color: #00d4ff; }
            </style>
        </head>
        <body>${html}</body>
        </html>
    `);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function copyOutput(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    navigator.clipboard.writeText(element.value || element.textContent).then(() => {
        // Visual feedback
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = originalText, 1500);
    });
}

function copyText(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    navigator.clipboard.writeText(element.textContent).then(() => {
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => btn.textContent = originalText, 1500);
    });
}

// Make functions globally available
window.showSection = showSection;
window.switchHashTab = switchHashTab;
window.computeHash = computeHash;
window.computeHMAC = computeHMAC;
window.encodeBase64 = encodeBase64;
window.decodeBase64 = decodeBase64;
window.encodeHex = encodeHex;
window.decodeHex = decodeHex;
window.encodeURL = encodeURL;
window.decodeURL = decodeURL;
window.decodeJWT = decodeJWT;
window.verifyJWT = verifyJWT;
window.loadExampleJWT = loadExampleJWT;
window.toggleCheatsheet = toggleCheatsheet;
window.convertData = convertData;
window.prettifyInput = prettifyInput;
window.minifyInput = minifyInput;
window.clearInput = clearInput;
window.swapFormats = swapFormats;
window.navigatePath = navigatePath;
window.validateSchema = validateSchema;
window.downloadOutput = downloadOutput;
window.switchHexTab = switchHexTab;
window.setHexInputType = setHexInputType;
window.analyzeHex = analyzeHex;
window.updateHexView = updateHexView;
window.switchChecksumTab = switchChecksumTab;
window.lookupHash = lookupHash;
window.showHashDB = showHashDB;
window.copyOutput = copyOutput;
window.copyText = copyText;

