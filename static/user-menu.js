document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('userMenuBtn');
    const menu = document.getElementById('userMenu');
    if (!btn || !menu) return;
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        menu.classList.toggle('hidden');
    });
    menu.addEventListener('click', (e) => e.stopPropagation());
    document.addEventListener('click', () => menu.classList.add('hidden'));
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') menu.classList.add('hidden');
    });
});

// Dark / light mode toggle in the top bar. The saved choice is applied
// before the page styles load by the snippet in each page's <head>;
// this only handles the click and remembers the new choice.
document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('themeToggle');
    if (!toggle) return;
    // The icon names the mode the button switches to: a sun while the
    // app is dark (click for light), a moon while it is light.
    const showIcon = () => {
        toggle.textContent = document.documentElement.getAttribute('data-theme') === 'light' ? '\u263E' : '\u2600';
    };
    showIcon();
    toggle.addEventListener('click', () => {
        const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        try { localStorage.setItem('CRIMSONLOCO-theme', next); } catch (e) {}
        showIcon();
    });
});
