// shared minimal helpers
async function fetchJSON(url, opts = {}) {
    const res = await fetch(url, opts);
    try { return await res.json(); } catch (e) { return null; }
}
function notify(msg) { alert(msg); }
