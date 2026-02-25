/**
 * RAID Monitor - Main Application JavaScript
 * Handles HTMX events, relative time formatting, Chart.js init,
 * Alpine.js components, language switching, CSRF, toasts, and auto-refresh.
 */

(function () {
  'use strict';

  /* ==========================================================================
     I18N - Simple dict-based translations
     ========================================================================== */
  const TRANSLATIONS = {
    ru: {
      'just now': 'только что',
      '{n} sec ago': '{n} сек назад',
      '{n} min ago': '{n} мин назад',
      '{n} hr ago': '{n} ч назад',
      '{n} day ago': '{n} д назад',
      '{n} days ago': '{n} д назад',
      'offline': 'оффлайн',
      'Settings saved': 'Настройки сохранены',
      'Error': 'Ошибка',
      'Success': 'Успешно',
      'Connection successful': 'Подключение успешно',
      'Connection failed': 'Подключение не удалось',
      'Test message sent': 'Тестовое сообщение отправлено',
      'Alert resolved': 'Оповещение решено',
      'Logs collected': 'Логи собраны',
      'Debug mode updated': 'Режим отладки обновлен',
      'Loading...': 'Загрузка...'
    },
    en: {}
  };

  function getLang() {
    const meta = document.querySelector('meta[name="language"]');
    if (meta) return meta.getAttribute('content') || 'en';
    const cookie = document.cookie.split(';').find(c => c.trim().startsWith('lang='));
    if (cookie) return cookie.split('=')[1].trim();
    return 'en';
  }

  function t(key, params) {
    const lang = getLang();
    let text = (TRANSLATIONS[lang] && TRANSLATIONS[lang][key]) || key;
    if (params) {
      Object.keys(params).forEach(k => {
        text = text.replace('{' + k + '}', params[k]);
      });
    }
    return text;
  }

  /* ==========================================================================
     CSRF Token
     ========================================================================== */
  function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  /* Inject CSRF token into all HTMX requests */
  document.addEventListener('htmx:configRequest', function (event) {
    const token = getCsrfToken();
    if (token) {
      event.detail.headers['X-CSRFToken'] = token;
    }
  });

  /* Inject CSRF token into all fetch/XHR requests */
  const originalFetch = window.fetch;
  window.fetch = function (url, options) {
    options = options || {};
    if (options.method && options.method.toUpperCase() !== 'GET') {
      options.headers = options.headers || {};
      if (!options.headers['X-CSRFToken']) {
        options.headers['X-CSRFToken'] = getCsrfToken();
      }
    }
    return originalFetch.call(this, url, options);
  };

  /* ==========================================================================
     Relative Time Formatting
     ========================================================================== */
  function formatRelativeTime(timestamp) {
    if (!timestamp) return 'N/A';

    const now = new Date();
    let date;

    if (typeof timestamp === 'string') {
      date = new Date(timestamp);
    } else if (typeof timestamp === 'number') {
      date = new Date(timestamp * 1000);
    } else {
      return 'N/A';
    }

    if (isNaN(date.getTime())) return 'N/A';

    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);

    if (diffSec < 10) return t('just now');
    if (diffSec < 60) return t('{n} sec ago', { n: diffSec });
    if (diffMin < 60) return t('{n} min ago', { n: diffMin });
    if (diffHr < 24) return t('{n} hr ago', { n: diffHr });
    if (diffDay === 1) return t('{n} day ago', { n: 1 });
    if (diffDay < 30) return t('{n} days ago', { n: diffDay });

    return date.toLocaleDateString(getLang() === 'ru' ? 'ru-RU' : 'en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  }

  function updateAllRelativeTimes() {
    document.querySelectorAll('.relative-time[data-timestamp]').forEach(function (el) {
      var ts = el.getAttribute('data-timestamp');
      if (ts) {
        el.textContent = formatRelativeTime(ts);
      }
    });
  }

  /* ==========================================================================
     Toast Notifications
     ========================================================================== */
  function showToast(message, type) {
    type = type || 'info';
    var container = document.getElementById('toast-container');
    if (!container) return;

    var iconMap = {
      success: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check-circle-fill text-success me-2" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>',
      error: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle-fill text-danger me-2" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>',
      warning: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-circle-fill text-warning me-2" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8 4a.905.905 0 0 0-.9.995l.35 3.507a.552.552 0 0 0 1.1 0l.35-3.507A.905.905 0 0 0 8 4zm.002 6a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"/></svg>',
      info: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-info-circle-fill text-info me-2" viewBox="0 0 16 16"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.399l-.442-.02.024-.416 2.338-.24zm-.14-2.788a.96.96 0 1 1 0-1.92.96.96 0 0 1 0 1.92z"/></svg>'
    };

    var bgMap = {
      success: 'bg-white',
      error: 'bg-white',
      warning: 'bg-white',
      info: 'bg-white'
    };

    var toastEl = document.createElement('div');
    toastEl.className = 'toast ' + (bgMap[type] || 'bg-white') + ' fade-in';
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.innerHTML =
      '<div class="toast-body d-flex align-items-center">' +
        (iconMap[type] || iconMap.info) +
        '<span>' + message + '</span>' +
        '<button type="button" class="btn-close ms-auto" data-bs-dismiss="toast" aria-label="Close"></button>' +
      '</div>';

    container.appendChild(toastEl);

    var toast = new bootstrap.Toast(toastEl, { delay: 5000 });
    toast.show();

    toastEl.addEventListener('hidden.bs.toast', function () {
      toastEl.remove();
    });
  }

  /* ==========================================================================
     HTMX Event Handlers
     ========================================================================== */

  /* Show loading spinner during requests */
  document.addEventListener('htmx:beforeRequest', function () {
    /* Optional: add global loading indicator */
  });

  /* Handle successful swaps */
  document.addEventListener('htmx:afterSwap', function (event) {
    /* Re-initialize Bootstrap tooltips in new content */
    var tooltipTriggers = event.detail.target.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipTriggers.forEach(function (el) {
      new bootstrap.Tooltip(el);
    });

    /* Update relative times in new content */
    event.detail.target.querySelectorAll('.relative-time[data-timestamp]').forEach(function (el) {
      var ts = el.getAttribute('data-timestamp');
      if (ts) {
        el.textContent = formatRelativeTime(ts);
      }
    });
  });

  /* Handle HTMX response errors */
  document.addEventListener('htmx:responseError', function (event) {
    var status = event.detail.xhr.status;
    if (status === 401) {
      window.location.href = '/login';
    } else if (status === 403) {
      showToast(t('Error') + ': Access denied', 'error');
    } else if (status >= 500) {
      showToast(t('Error') + ': Server error (' + status + ')', 'error');
    } else {
      showToast(t('Error') + ': Request failed (' + status + ')', 'error');
    }
  });

  /* Handle HTMX afterRequest for showing success messages from headers */
  document.addEventListener('htmx:afterRequest', function (event) {
    var xhr = event.detail.xhr;
    if (!xhr) return;

    /* Check for custom toast header */
    var toastMsg = xhr.getResponseHeader('HX-Trigger-After-Swap');
    if (toastMsg) {
      try {
        var parsed = JSON.parse(toastMsg);
        if (parsed.showToast) {
          showToast(parsed.showToast.message, parsed.showToast.type);
        }
      } catch (e) {
        /* ignore parsing errors */
      }
    }

    /* Show success toast for PUT/POST/DELETE with 2xx status */
    if (xhr.status >= 200 && xhr.status < 300) {
      var method = (event.detail.requestConfig && event.detail.requestConfig.verb) || '';
      method = method.toUpperCase();
      if (method === 'PUT' || method === 'DELETE') {
        /* Only show toast if hx-swap is "none" (API calls without content swap) */
        var swapAttr = event.detail.elt.getAttribute('hx-swap');
        if (swapAttr === 'none') {
          showToast(t('Success'), 'success');
        }
      }
    }
  });

  /* ==========================================================================
     Language Switcher
     ========================================================================== */
  function switchLanguage(lang) {
    document.cookie = 'lang=' + lang + ';path=/;max-age=31536000';

    // Persist to DB for logged-in users
    fetch('/set-preference', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: 'lang', value: lang })
    }).catch(function () { /* not logged in, cookie is enough */ });

    var url = new URL(window.location.href);
    url.searchParams.set('lang', lang);
    window.location.href = url.toString();
  }

  /* Intercept lang toggle clicks */
  document.addEventListener('click', function (event) {
    var link = event.target.closest('a[href*="?lang="]');
    if (link) {
      event.preventDefault();
      var url = new URL(link.href, window.location.origin);
      var lang = url.searchParams.get('lang');
      if (lang) {
        switchLanguage(lang);
      }
    }
  });

  /* ==========================================================================
     Chart.js Helpers
     ========================================================================== */
  function isDarkTheme() {
    return document.documentElement.getAttribute('data-bs-theme') === 'dark';
  }

  function chartGridColor() {
    return isDarkTheme() ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.05)';
  }

  function chartTickColor() {
    return isDarkTheme() ? '#9ca3af' : '#666';
  }

  function initSmartChart(canvasId, labels, data, label) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    var ctx = canvas.getContext('2d');

    return new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: label || 'Value',
          data: data,
          borderColor: 'rgba(13, 110, 253, 1)',
          backgroundColor: 'rgba(13, 110, 253, 0.1)',
          fill: true,
          tension: 0.3,
          pointRadius: 2,
          pointHoverRadius: 5,
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            mode: 'index',
            intersect: false
          }
        },
        scales: {
          x: {
            display: true,
            grid: {
              display: false
            },
            ticks: {
              font: { size: 10 },
              maxRotation: 0,
              color: chartTickColor()
            }
          },
          y: {
            display: true,
            beginAtZero: true,
            grid: {
              color: chartGridColor()
            },
            ticks: {
              font: { size: 10 },
              color: chartTickColor()
            }
          }
        },
        interaction: {
          mode: 'nearest',
          axis: 'x',
          intersect: false
        }
      }
    });
  }

  function initTemperatureChart(canvasId, labels, temperatures) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    var ctx = canvas.getContext('2d');

    var bgColors = temperatures.map(function (temp) {
      if (temp > 50) return 'rgba(220, 53, 69, 0.7)';
      if (temp > 40) return 'rgba(255, 193, 7, 0.7)';
      return 'rgba(25, 135, 84, 0.7)';
    });

    return new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Temperature (C)',
          data: temperatures,
          backgroundColor: bgColors,
          borderRadius: 4,
          barThickness: 20
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: chartTickColor() }
          },
          y: {
            beginAtZero: true,
            max: 100,
            grid: { color: chartGridColor() },
            ticks: { color: chartTickColor() }
          }
        }
      }
    });
  }

  /* ==========================================================================
     Alpine.js Global Components
     ========================================================================== */
  document.addEventListener('alpine:init', function () {
    /* Filter store for dashboard */
    Alpine.store('filters', {
      search: '',
      status: '',
      sort: 'hostname'
    });
  });

  /* ==========================================================================
     Auto-refresh
     ========================================================================== */
  /* Dashboard auto-refresh is handled by HTMX hx-trigger="every 60s"
     This is an additional mechanism for non-HTMX pages */

  var autoRefreshInterval = null;

  function startAutoRefresh(intervalMs) {
    intervalMs = intervalMs || 60000;
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
    autoRefreshInterval = setInterval(function () {
      updateAllRelativeTimes();
    }, 30000);
  }

  function stopAutoRefresh() {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
    }
  }

  /* ==========================================================================
     Bootstrap Tooltip Init
     ========================================================================== */
  function initTooltips() {
    var tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipTriggerList.forEach(function (el) {
      new bootstrap.Tooltip(el);
    });
  }

  /* ==========================================================================
     DOMContentLoaded Init
     ========================================================================== */
  document.addEventListener('DOMContentLoaded', function () {
    updateAllRelativeTimes();
    initTooltips();
    startAutoRefresh();
  });

  /* ==========================================================================
     Public API (accessible from templates)
     ========================================================================== */
  window.RaidMonitor = {
    formatRelativeTime: formatRelativeTime,
    updateAllRelativeTimes: updateAllRelativeTimes,
    showToast: showToast,
    switchLanguage: switchLanguage,
    initSmartChart: initSmartChart,
    initTemperatureChart: initTemperatureChart,
    getCsrfToken: getCsrfToken,
    t: t,
    startAutoRefresh: startAutoRefresh,
    stopAutoRefresh: stopAutoRefresh
  };

})();

/* ==========================================================================
   Theme Toggle (global scope for onclick handlers)
   ========================================================================== */
function toggleTheme() {
  var html = document.documentElement;
  var current = html.getAttribute('data-bs-theme') || 'light';
  var next = current === 'dark' ? 'light' : 'dark';

  html.setAttribute('data-bs-theme', next);

  // Toggle sun/moon icons
  document.querySelectorAll('.theme-icon-light').forEach(function (el) {
    el.classList.toggle('d-none', next === 'dark');
  });
  document.querySelectorAll('.theme-icon-dark').forEach(function (el) {
    el.classList.toggle('d-none', next !== 'dark');
  });

  // Set cookie immediately for instant persistence
  document.cookie = 'theme=' + next + ';path=/;max-age=31536000;SameSite=Lax';

  // Persist to DB for logged-in users
  fetch('/set-preference', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: 'theme', value: next })
  }).catch(function () { /* not logged in, cookie is enough */ });
}
