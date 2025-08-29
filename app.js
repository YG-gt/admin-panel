(function () {
    // ===== helpers =====
    const qs = (sel, root) => (root || document).querySelector(sel);
    const qsa = (sel, root) => Array.from((root || document).querySelectorAll(sel));

    // ====== USERS page logic ======
    (function usersPage() {
        const modal = qs('#pwdModal');
        const uidEl = qs('#pwdUid');
        const pwdNew = qs('#pwdNew');

        // Есть ли что-то, характерное для users-страницы?
        const isUsersPage = !!qs('.js-open-pwd') || !!qs('.js-confirm-form') || !!modal;
        if (!isUsersPage) return;

        // Открыть модалку смены пароля
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.js-open-pwd');
            if (!btn) return;
            const uid = btn.getAttribute('data-uid') || '';
            if (uidEl) uidEl.value = uid;
            if (pwdNew) pwdNew.value = '';
            if (modal) modal.style.display = 'block';
            setTimeout(() => { if (pwdNew) pwdNew.focus(); }, 50);
        });

        // Закрыть модалку
        function closeModal() { if (modal) modal.style.display = 'none'; }
        document.addEventListener('click', (e) => {
            if (e.target && e.target.classList && e.target.classList.contains('js-close-pwd')) {
                closeModal();
            }
        });
        // клик «вне» модалки
        document.addEventListener('click', (e) => {
            if (!modal) return;
            if (e.target === modal) closeModal();
        });
        // Esc
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

        // Подтверждения для форм действий
        document.addEventListener('submit', (e) => {
            const f = e.target;
            if (!f || !f.classList) return;
            if (f.classList.contains('js-confirm-form')) {
                const msg = f.getAttribute('data-confirm') || 'Are you sure?';
                if (!confirm(msg)) e.preventDefault();
            }
        });
    })();

    // ====== ROOMS page logic ======
    (function roomsPage() {
        // Признаки rooms-страницы
        const bulkForm = qs('#bulkForm');
        const checkAll = qs('#checkAll');
        const bulkBtn = qs('#bulkBtn');
        const isRoomsPage = !!bulkForm || !!checkAll || qsa('.roomChk').length > 0;
        if (!isRoomsPage) return;

        function syncBulkBtn() {
            if (!bulkBtn) return;
            const any = qsa('.roomChk:checked').length > 0;
            bulkBtn.disabled = !any;
        }

        if (checkAll) {
            checkAll.addEventListener('change', () => {
                qsa('.roomChk').forEach(cb => cb.checked = checkAll.checked);
                syncBulkBtn();
            });
        }

        document.addEventListener('change', (e) => {
            if (e.target && e.target.classList && e.target.classList.contains('roomChk')) {
                syncBulkBtn();
            }
        });

        if (bulkForm) {
            bulkForm.addEventListener('submit', (e) => {
                const cnt = qsa('.roomChk:checked').length;
                if (cnt === 0) { e.preventDefault(); return; }
                if (!confirm('Request deletion for ' + cnt + ' room(s)?')) {
                    e.preventDefault();
                }
            });
        }

        document.addEventListener('DOMContentLoaded', syncBulkBtn);
    })();
})();
