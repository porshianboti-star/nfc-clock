// NFC attendance clock — shared browser helpers. No framework, no build step.
(function () {
  'use strict';
  var API = window.CLOCK_API;
  var TOKEN_KEY = 'clock_worker_token';

  function qs(name) { return new URLSearchParams(location.search).get(name) || ''; }

  function api(path, opts) {
    opts = opts || {};
    var headers = { 'content-type': 'application/json' };
    if (opts.admin) headers['x-admin-key'] = opts.admin;
    if (opts.worker) headers['x-worker-token'] = opts.worker;
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, opts.timeout || 15000) : null;
    return fetch(API + path, {
      method: opts.method || (opts.body ? 'POST' : 'GET'),
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      signal: ctrl ? ctrl.signal : undefined,
      cache: 'no-store'
    }).then(function (r) {
      if (timer) clearTimeout(timer);
      var ct = r.headers.get('content-type') || '';
      var p = ct.indexOf('text/csv') === 0 ? r.text() : r.json().catch(function () { return {}; });
      return p.then(function (data) {
        if (!r.ok) { var e = new Error((data && data.error) || ('http_' + r.status)); e.status = r.status; e.data = data; throw e; }
        return data;
      });
    }, function (err) {
      if (timer) clearTimeout(timer);
      var e = new Error(err && err.name === 'AbortError' ? 'timeout' : 'network');
      throw e;
    });
  }

  var MSG = {
    network: 'אין חיבור לאינטרנט. נסה שוב.',
    timeout: 'השרת לא ענה בזמן. נסה שוב.',
    not_bound: 'הטלפון הזה עדיין לא מחובר לעובד.',
    worker_inactive: 'העובד הזה הושבת. פנה למנהל.',
    tag_unknown: 'המדבקה הזאת לא שייכת לעסק שלך או שנמחקה.',
    install_key_invalid: 'לינק ההתקנה לא תקין או בוטל. בקש לינק חדש מהמנהל.',
    admin_key_required: 'חסר לינק ניהול.',
    admin_key_invalid: 'לינק הניהול לא תקין.',
    rate_limited: 'יותר מדי ניסיונות. נסה שוב בעוד דקה.',
    internal: 'תקלה בשרת. נסה שוב.'
  };
  function msg(err) { return MSG[err && err.message] || ('שגיאה: ' + (err && err.message)); }

  function getToken() { try { return localStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; } }
  function setToken(t) { try { if (t) localStorage.setItem(TOKEN_KEY, t); else localStorage.removeItem(TOKEN_KEY); } catch (e) {} }

  // one GPS fix, never longer than `ms`; resolves null when denied / unavailable / slow
  function locate(ms) {
    return new Promise(function (resolve) {
      if (!navigator.geolocation) return resolve(null);
      var done = false;
      var t = setTimeout(function () { if (!done) { done = true; resolve(null); } }, ms || 7000);
      navigator.geolocation.getCurrentPosition(function (p) {
        if (done) return; done = true; clearTimeout(t);
        resolve({ lat: p.coords.latitude, lng: p.coords.longitude, accuracy: Math.round(p.coords.accuracy || 0) });
      }, function () { if (!done) { done = true; clearTimeout(t); resolve(null); } }, { enableHighAccuracy: true, timeout: ms || 7000, maximumAge: 30000 });
    });
  }

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  var toastEl;
  function toast(text) {
    if (!toastEl) { toastEl = document.createElement('div'); toastEl.className = 'toast'; document.body.appendChild(toastEl); }
    toastEl.textContent = text; toastEl.classList.add('show');
    clearTimeout(toastEl._t); toastEl._t = setTimeout(function () { toastEl.classList.remove('show'); }, 2200);
  }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).then(function () { toast('הועתק'); }, function () { prompt('העתק:', text); });
    prompt('העתק:', text); return Promise.resolve();
  }

  // base URL of this site (GitHub Pages project path or a custom domain)
  function siteBase() {
    var p = location.pathname.replace(/\/(t|s|d)\/?(index\.html)?$/, '/').replace(/index\.html$/, '');
    return location.origin + p;
  }

  function todayLocal(tz) {
    try { return new Intl.DateTimeFormat('en-CA', { timeZone: tz || 'Asia/Jerusalem', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date()); }
    catch (e) { return new Date().toISOString().slice(0, 10); }
  }

  window.Clock = { qs: qs, api: api, msg: msg, getToken: getToken, setToken: setToken, locate: locate, esc: esc, toast: toast, copy: copy, siteBase: siteBase, todayLocal: todayLocal };
})();
