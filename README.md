# ByteHackr Tools 🔐

A comprehensive, client-side security toolkit for hackers, pentesters, and developers. All processing happens entirely in your browser - no data is ever sent to external servers.

![ByteHackr Tools](https://img.shields.io/badge/100%25-Client--Side-00ff88?style=for-the-badge)
![No Tracking](https://img.shields.io/badge/Zero-Data%20Collection-00d4ff?style=for-the-badge)

## 🛠️ Tools Included

### 1. Hashing & Encoding Toolkit
- **Hash Algorithms**: MD5, SHA-1, SHA-256, SHA-512
- **HMAC**: HMAC-SHA256, HMAC-SHA512 with custom keys
- **Encoding**: Base64, Hex, URL encode/decode
- **File Hashing**: Drag & drop file support for computing checksums

### 2. JWT / Token Inspector
- Decode and pretty-print JWT tokens
- Visualize header, payload, and signature separately
- Analyze standard claims (exp, iat, sub, etc.)
- Verify signatures locally with HMAC algorithms
- Expiration detection

### 3. Regex Tester & Explainer
- Real-time pattern matching
- Highlighted matches in test string
- Capture group visualization
- Replace preview with group references
- Quick reference cheatsheet

### 4. YAML / JSON Converter & Validator
- Bidirectional JSON ↔ YAML conversion
- Pretty print and minify
- JSON Schema validation
- Path navigator for nested data
- Download converted output

### 5. Binary String / Hex Viewer
- View binary data as hex dump
- ASCII representation
- File signature detection (PE, ELF, PDF, ZIP, images, etc.)
- Support for text, hex string, and base64 input
- Configurable bytes per row

### 6. Checksum Lookup
- Calculate file checksums (MD5, SHA-1, SHA-256, SHA-512)
- Verify against expected hash values
- Compare two files for equality
- Local known-good hash database
- Optional VirusTotal API integration

## 🚀 Getting Started

### Option 1: Direct Use
Simply open `index.html` in any modern web browser.

### Option 2: Local Server
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx serve .

# Using PHP
php -S localhost:8000
```

Then visit `http://localhost:8000`

### Option 3: Deploy to Static Hosting
Upload all files to any static hosting service:
- GitHub Pages
- Netlify
- Vercel
- Cloudflare Pages

## 📁 Project Structure

```
tools.bytehackr.in/
├── index.html          # Main HTML file
├── css/
│   └── style.css       # Cyberpunk-themed styles
├── js/
│   ├── app.js          # Main application logic
│   └── md5.js          # MD5 hash implementation
├── LICENSE             # MIT License
└── README.md           # This file
```

## 🔒 Security & Privacy

- **100% Client-Side**: All processing happens in your browser
- **No External Calls**: By default, no data is sent to any server
- **No Tracking**: No analytics, cookies, or user tracking
- **Open Source**: Full transparency of all code

> **Note**: The optional VirusTotal lookup feature requires an API key and will send hash values (not file contents) to VirusTotal's servers. This is clearly marked and disabled by default.

## 🎨 Features

- **Modern UI**: Cyberpunk/hacker aesthetic with neon accents
- **Matrix Rain Background**: Animated canvas background
- **Responsive Design**: Works on desktop and mobile
- **Dark Theme**: Easy on the eyes for extended use
- **Keyboard Friendly**: Tab navigation support
- **Copy to Clipboard**: One-click copying for all outputs

## 🌐 Browser Support

- Chrome 80+
- Firefox 75+
- Safari 14+
- Edge 80+

## 📦 Dependencies

- [js-yaml](https://github.com/nodeca/js-yaml) - YAML parsing (loaded via CDN)
- Custom MD5 implementation (included)
- Web Crypto API (built into browsers)

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- **Live Site**: [tools.bytehackr.in](https://tools.bytehackr.in)
- **GitHub**: [github.com/bytehackr](https://github.com/bytehackr)

---

Built with ❤️ for the security community
