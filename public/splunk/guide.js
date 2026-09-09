document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(code.textContent);
      document.getElementById('copy-status').textContent = 'SPL copied. Replace the index and map event fields before running.';
    } catch {
      const selection = window.getSelection();
      const range = document.createRange(); range.selectNodeContents(code);
      selection.removeAllRanges(); selection.addRange(range);
      document.getElementById('copy-status').textContent = 'Clipboard unavailable. Query selected; use your browser’s Copy command.';
    }
  });
});
