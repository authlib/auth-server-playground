// Listen on the document, so that the buttons htmx swaps in work too.
document.addEventListener('click', event => {
    const button = event.target.closest('[data-copy]');
    if (!button) {
        return;
    }

    // Read the label once: a second click would read the "copied" label.
    const label = button.dataset.label ??= button.textContent;

    // The clipboard API only exists in secure contexts: HTTPS or localhost.
    const copied = navigator.clipboard
        ? navigator.clipboard.writeText(button.dataset.copy)
        : Promise.reject(new Error('No clipboard'));
    copied.then(() => {
        button.textContent = button.dataset.copied;
    }).catch(() => {
        button.textContent = button.dataset.failed;
    }).finally(() => {
        setTimeout(() => {
            button.textContent = label;
        }, 2000);
    });
});
