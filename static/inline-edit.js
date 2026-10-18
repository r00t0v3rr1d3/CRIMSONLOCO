document.addEventListener('DOMContentLoaded', () => {
    const cfg = window.CRIMSONLOCO_FIELD_EDIT;
    if (!cfg) return;
    const statusMessage = document.getElementById('statusMessage');
    const updatedMeta = document.getElementById('updatedMeta');
    let version = cfg.version;

    const showValue = (group) => {
        const span = group.querySelector('.editable-value');
        const v = group.dataset.value;
        span.textContent = v;
        span.classList.toggle('not-set', v === '');
    };

    document.querySelectorAll('.editable-field-group').forEach((group) => {
        const span = group.querySelector('.editable-value');
        const input = group.querySelector('.editable-input');
        const buttons = group.querySelector('.action-buttons');
        const saveButton = buttons.querySelector('.save-button');
        const cancelButton = buttons.querySelector('.cancel-button');
        const label = group.dataset.label;

        showValue(group);

        const toEdit = () => {
            input.value = group.dataset.value;
            span.classList.add('hidden');
            input.classList.remove('hidden');
            buttons.classList.remove('hidden');
            input.focus();
            if (input.select) input.select();
        };
        const toDisplay = () => {
            input.classList.add('hidden');
            buttons.classList.add('hidden');
            span.classList.remove('hidden');
        };

        span.addEventListener('click', toEdit);
        cancelButton.addEventListener('click', () => {
            toDisplay();
            statusMessage.textContent = label + ' changes canceled.';
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') cancelButton.click();
            if (e.key === 'Enter' && input.tagName === 'INPUT') saveButton.click();
        });

        saveButton.addEventListener('click', async () => {
            statusMessage.textContent = 'Saving ' + label + '...';
            const body = new URLSearchParams({
                csrf_token: cfg.csrf,
                field: group.dataset.field,
                value: input.value,
                version: String(version)
            });
            try {
                const resp = await fetch(cfg.url, { method: 'POST', body });
                const data = await resp.json();
                if (resp.ok) {
                    version = data.version;
                    group.dataset.value = data.value;
                    showValue(group);
                    if (updatedMeta && data.updated_at) {
                        updatedMeta.textContent = data.updated_at + ' UTC by ' + data.updated_by;
                    }
                    statusMessage.textContent = label + ' saved.';
                    toDisplay();
                } else {
                    // 400 validation or 409 conflict: keep the editor's text
                    // in place for 400; for a conflict, adopt the server's
                    // current value and version so a retry can go through.
                    statusMessage.textContent = data.error || 'Save failed.';
                    if (resp.status === 409 && typeof data.value === 'string') {
                        version = data.version;
                        group.dataset.value = data.value;
                        showValue(group);
                        toDisplay();
                    }
                }
            } catch (err) {
                statusMessage.textContent = 'Save failed: ' + err.message;
            }
        });
    });
});
