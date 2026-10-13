/**
 * REVSHIELD — Static Overview Website Script
 * Theme management, interactive extension mockup, and smooth UI behavior
 */

(function () {
  'use strict';

  // --- 1. Theme Management (Light / Dark) ---
  const THEME_STORAGE_KEY = 'revshield-overview-theme';
  const themeToggleBtns = document.querySelectorAll('.theme-toggle');

  function getPreferredTheme() {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved) return saved;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_STORAGE_KEY, theme);
    updateThemeToggleIcons(theme);
  }

  function updateThemeToggleIcons(theme) {
    themeToggleBtns.forEach((btn) => {
      btn.innerHTML =
        theme === 'dark'
          ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>'
          : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>';
    });
  }

  // Initialize theme
  const initialTheme = getPreferredTheme();
  setTheme(initialTheme);

  themeToggleBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      setTheme(current === 'dark' ? 'light' : 'dark');
    });
  });

  // --- 2. Mobile Menu Navigation ---
  const mobileToggle = document.querySelector('.mobile-toggle');
  const mobileMenu = document.querySelector('.mobile-menu');

  if (mobileToggle && mobileMenu) {
    mobileToggle.addEventListener('click', () => {
      mobileMenu.classList.toggle('open');
    });

    // Close on link click
    mobileMenu.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        mobileMenu.classList.remove('open');
      });
    });
  }

  // --- 3. Interactive Browser Extension Mockup Demo ---
  const switchMockup = document.getElementById('demo-switch');
  const statusTag = document.getElementById('demo-status');
  const trackersCount = document.getElementById('demo-trackers');
  const adsCount = document.getElementById('demo-ads');

  if (switchMockup && statusTag && trackersCount && adsCount) {
    let isProtected = true;

    switchMockup.addEventListener('click', () => {
      isProtected = !isProtected;
      if (isProtected) {
        switchMockup.classList.remove('off');
        statusTag.textContent = 'PROTECTED';
        statusTag.className = 'popup-tag';
        trackersCount.textContent = '7';
        adsCount.textContent = '12';
      } else {
        switchMockup.classList.add('off');
        statusTag.textContent = 'WHITELISTED';
        statusTag.className = 'popup-tag';
        statusTag.style.background = 'var(--shield-warn-bg)';
        statusTag.style.color = 'var(--shield-warn)';
        statusTag.style.borderColor = 'rgba(245, 158, 11, 0.2)';
        trackersCount.textContent = '0';
        adsCount.textContent = '0';
      }
    });
  }

  // --- 4. Code Copy to Clipboard ---
  document.querySelectorAll('.code-copy-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const codeEl = document.getElementById(targetId);
      if (codeEl) {
        const textToCopy = codeEl.innerText;
        navigator.clipboard.writeText(textToCopy).then(() => {
          const originalText = btn.textContent;
          btn.textContent = 'Copied!';
          btn.style.background = 'var(--shield-safe)';
          btn.style.color = '#ffffff';
          setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
            btn.style.color = '';
          }, 2000);
        });
      }
    });
  });

  // --- 5. Active Navigation Link Spy ---
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  window.addEventListener('scroll', () => {
    let currentId = '';
    const scrollY = window.pageYOffset;

    sections.forEach((section) => {
      const sectionTop = section.offsetTop - 120;
      const sectionHeight = section.offsetHeight;
      if (scrollY >= sectionTop && scrollY < sectionTop + sectionHeight) {
        currentId = section.getAttribute('id');
      }
    });

    navLinks.forEach((link) => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${currentId}`) {
        link.classList.add('active');
      }
    });
  });
})();
