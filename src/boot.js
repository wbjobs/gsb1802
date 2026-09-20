// Load this tiny classic script BEFORE any other script (ideally first in
// <head>). It records securitypolicyviolation events that fire before the
// module bundle has loaded. Once CspMonitor starts it drains the buffer and
// boot forwards subsequent events directly to it.
(function () {
  if (window.__cspBootInstalled) return;
  window.__cspBootInstalled = true;
  window.__cspEarlyEvents = [];

  // Exposed so the real monitor can remove this listener once it takes over,
  // otherwise each event would be delivered to both listeners (double count).
  function bootListener(event) {
    if (typeof window.__cspMonitorCapture === 'function') {
      window.__cspMonitorCapture(event);
    } else {
      window.__cspEarlyEvents.push(event);
    }
  }
  window.__cspBootListener = bootListener;
  document.addEventListener(
    'securitypolicyviolation',
    bootListener,
    true
  );
})();
