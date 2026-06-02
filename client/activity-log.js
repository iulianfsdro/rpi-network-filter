// activity-log.js — durable, lightweight per-command diagnostic log.
//
// What problem this solves: when a command misbehaves at the car
// (slow, wrong fault, weird retry pattern), you currently have to
// open DevTools, look at the console, capture before the page
// reloads, paste back. That's friction at the moment you most need
// to be efficient. This module is a 100-entry ring buffer in
// localStorage that records every command attempt + outcome, plus
// the bits that matter for diagnosis (domain, attempt #, fault,
// timing). You can see it inline on the page, and "Copy as JSON"
// dumps a paste-able snapshot.
//
// localStorage budget: ~100 entries × ~200 bytes = 20 KB. Trivial.
// Persists across reloads so a "page froze" report still has the
// activity that led up to it.

const STORAGE_KEY  = 'airgap-activity-log';
const MAX_ENTRIES  = 100;

// _read pulls the log out of localStorage, returning [] on any
// parse failure (corrupted JSON, quota exceeded last write, etc.).
function _read() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function _write(entries) {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
    } catch (e) {
        // localStorage quota hit. Halve and retry once — keeps the
        // most recent half, drops the rest. We never throw on log
        // writes; logging shouldn't break the command path.
        try {
            const halved = entries.slice(-Math.floor(MAX_ENTRIES / 2));
            localStorage.setItem(STORAGE_KEY, JSON.stringify(halved));
        } catch { /* give up silently */ }
    }
}

// logActivity records one command attempt or significant event.
// entry shape: { label, domain, attempt, fault, durationMs, result,
// vin, note }. All fields optional except `label` and `result`.
//
// `result` is one of:
//   'ok'        — command succeeded
//   'retry'     — fault detected, will retry
//   'refresh'   — session-stale fault detected, refreshing session
//   'evict'     — refresh failed, full evict + handshake
//   'error'     — final failure, surfaced to user
//   'event'     — generic event (refresh, connect, forget, etc.)
function logActivity(entry) {
    const at = entry.at || Date.now();
    const row = {
        at,
        label:       entry.label || '?',
        result:      entry.result || 'event',
        domain:      entry.domain,        // 2 (VCSEC) or 3 (Infotainment), or undefined
        attempt:     entry.attempt,        // 1..10, or undefined
        fault:       entry.fault,          // numeric fault code, or undefined
        durationMs:  entry.durationMs,     // command round-trip in ms
        vin:         entry.vin,
        note:        entry.note,           // free-form
    };
    const entries = _read();
    entries.push(row);
    if (entries.length > MAX_ENTRIES) entries.splice(0, entries.length - MAX_ENTRIES);
    _write(entries);
}

// getRecentActivity returns the most recent N entries, newest first.
function getRecentActivity(limit) {
    const entries = _read();
    const out = entries.slice(-(limit || 50)).reverse();
    return out;
}

function clearActivityLog() {
    try { localStorage.removeItem(STORAGE_KEY); } catch {}
}

window.airgap = window.airgap || {};
Object.assign(window.airgap, {
    logActivity,
    getRecentActivity,
    clearActivityLog,
});
