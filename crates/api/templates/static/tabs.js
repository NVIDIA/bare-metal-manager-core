/*
 * Tab switching with a sliding indicator.
 *
 * Usage in any page that extends base.html:
 *
 *   <div class="tab-nav">
 *       <button class="tab-button active" data-tab="overview">Overview</button>
 *       <button class="tab-button" data-tab="details">Details</button>
 *       <div class="tab-indicator"></div>
 *   </div>
 *   <div class="tab-content active" id="tab-overview"> ... </div>
 *   <div class="tab-content" id="tab-details"> ... </div>
 *
 */
(function() {
    function initTabs(nav) {
        const indicator = nav.querySelector('.tab-indicator');

        function moveIndicator(button) {
            if (!indicator || !button) return;
            indicator.style.width = button.offsetWidth + 'px';
            indicator.style.transform = 'translateX(' + button.offsetLeft + 'px)';
        }

        function setActive(button) {
            const currentBtn = nav.querySelector('.tab-button.active');
            if (currentBtn) currentBtn.classList.remove('active');
            button.classList.add('active');

            const currentContent = document.querySelector('.tab-content.active');
            if (currentContent) currentContent.classList.remove('active');
            const targetId = 'tab-' + button.getAttribute('data-tab');
            const nextContent = document.getElementById(targetId);
            if (nextContent) nextContent.classList.add('active');

            moveIndicator(button);

            // Keep the URL in sync with the active tab so reload / bookmark
            // restore works.
            const url = new URL(window.location.href);
            url.searchParams.set('tab', button.getAttribute('data-tab'));
            history.replaceState(null, '', url.toString());
        }

        const initial = nav.querySelector('.tab-button.active')
            || nav.querySelector('.tab-button');
        if (initial) {
            moveIndicator(initial);
        }

        nav.addEventListener('click', function(e) {
            const button = e.target.closest('.tab-button');
            if (!button || !nav.contains(button)) return;
            setActive(button);
        });

        window.addEventListener('resize', function() {
            moveIndicator(nav.querySelector('.tab-button.active'));
        });
    }

    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.tab-nav').forEach(initTabs);
    });
})();
