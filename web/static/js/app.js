const api = {
    async request(method, url, body) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin'
        };
        if (body) opts.body = JSON.stringify(body);
        const res = await fetch(url, opts);
        if (res.status === 401) {
            window.location = '/login';
            throw new Error('unauthorized');
        }
        const data = await res.json();
        if (!res.ok) {
            notify(data.error || 'Request failed', 'error');
            throw new Error(data.error || 'Request failed');
        }
        return data;
    },
    get:    (url)       => api.request('GET', url),
    post:   (url, data) => api.request('POST', url, data),
    put:    (url, data) => api.request('PUT', url, data),
    delete: (url)       => api.request('DELETE', url),
};

function notify(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = msg;
    container.appendChild(toast);

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

async function logout() {
    await api.post('/api/logout');
    window.location = '/login';
}

function formatBytes(bytes) {
    bytes = parseInt(bytes) || 0;
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    seconds = parseFloat(seconds) || 0;
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
}
