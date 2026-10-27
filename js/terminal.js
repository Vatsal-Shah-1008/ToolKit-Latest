class SecOpsTerminal {
    constructor(elementId) {
        this.el = document.getElementById(elementId);
        this.logs = [];
    }

    log(message, type = 'info') {
        if (!this.el) return;
        const now = new Date();
        const ts = now.toTimeString().split(' ')[0];

        // Format message and determine syntax class
        let cssClass = 'log-info';
        if (message.startsWith('[+]') || message.includes('SUCCESS') || message.includes('PASS') || message.includes('VALID')) {
            cssClass = 'log-success';
        } else if (message.startsWith('[!]') || message.includes('WARNING') || message.includes('WARN')) {
            cssClass = 'log-warning';
        } else if (message.startsWith('[-]') || message.includes('FAIL') || message.includes('CRITICAL') || message.includes('EXPIRED')) {
            cssClass = 'log-danger';
        }

        const line = document.createElement('div');
        line.className = `log-line ${cssClass}`;
        line.innerHTML = `<span class="log-ts">[${ts}]</span> <span>${this.escapeHtml(message)}</span>`;

        this.el.appendChild(line);
        this.logs.push(`[${ts}] ${message}`);

        // Auto-scroll
        this.el.scrollTop = this.el.scrollHeight;
    }

    clear() {
        if (!this.el) return;
        this.el.innerHTML = '<div class="log-line log-info"><span class="log-ts">[' + (new Date().toTimeString().split(' ')[0]) + ']</span> <span>Terminal cleared. System ready.</span></div>';
        this.logs = [];
    }

    copy() {
        const text = this.logs.join('\n');
        if (!text) return;
        navigator.clipboard.writeText(text).then(() => {
            showToast('Terminal logs copied to clipboard!');
        });
    }

    escapeHtml(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}

// Global Terminal Instance
window.term = new SecOpsTerminal('terminal-output');
