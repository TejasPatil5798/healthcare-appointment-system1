// shared minimal helpers
async function fetchJSON(url, opts = {}) {
    const res = await fetch(url, opts);
    try { return await res.json(); } catch (e) { return null; }
}
function notify(msg) { alert(msg); }


const menuToggle = document.getElementById('menu-toggle');
const navLinks = document.getElementById('nav-links');

menuToggle.addEventListener('click', () => {
    navLinks.classList.toggle('active');
});