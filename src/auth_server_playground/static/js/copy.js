// The timers that bring each button back to its first label.
const resets = new WeakMap();

// Listen on the document, so that the buttons htmx swaps in work too.
document.addEventListener('click', event => {
    const button = event.target.closest('[data-copy]');
    if (!button) {
        return;
    }
    const group = button.closest('[role="group"]');
    const value = group.querySelector('input').value;
    const status = group.nextElementSibling;

    const show = state => {
        button.dataset.state = state;
        status.textContent = button.querySelector(`[data-when="${state}"]`).textContent;
    };

    // The clipboard API only exists in secure contexts: HTTPS or localhost.
    const copied = navigator.clipboard
        ? navigator.clipboard.writeText(value)
        : Promise.reject(new Error('No clipboard'));
    copied.then(() => show('copied')).catch(() => show('failed')).finally(() => {
        clearTimeout(resets.get(button));
        resets.set(button, setTimeout(() => {
            delete button.dataset.state;
            status.textContent = '';
        }, 2000));
    });
});
