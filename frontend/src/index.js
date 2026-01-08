import './index.css';
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.js';
import StudioPage from './StudioPage';
import AutomationSettingsPage from './AutomationSettingsPage';

const root = ReactDOM.createRoot(document.getElementById('root'));

function getRoute() {
  try {
    const hash = window.location.hash || '';
    const path = window.location.pathname || '';
    const isStudio = (hash && hash.includes('/automation-studio')) || path === '/automation-studio' || path.startsWith('/automation-studio/');
    const isAutomationSettings = (hash && hash.includes('/automation-settings')) || path === '/automation-settings' || path.startsWith('/automation-settings/');
    const isSettings = (hash && hash.includes('/settings')) || path === '/settings' || path.startsWith('/settings/');
    if (isSettings || isAutomationSettings) return 'settings';
    if (isStudio) return 'studio';
    return 'app';
  } catch {
    return 'app';
  }
}

function RouterRoot() {
  const [route, setRoute] = React.useState(getRoute());

  React.useEffect(() => {
    const onChange = () => setRoute(getRoute());
    window.addEventListener('hashchange', onChange);
    window.addEventListener('popstate', onChange);
    return () => {
      window.removeEventListener('hashchange', onChange);
      window.removeEventListener('popstate', onChange);
    };
  }, []);

  return route === 'settings' ? <AutomationSettingsPage /> : (route === 'studio' ? <StudioPage /> : <App />);
}

root.render(<RouterRoot />);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals

// Register service worker for asset caching (production-safe)
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    try {
      const reloader = { fired: false };
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        if (reloader.fired) return;
        reloader.fired = true;
        try { window.location.reload(); } catch {}
      });
      navigator.serviceWorker.register('/sw.js', { updateViaCache: 'none' })
        .then((registration) => {
          try { registration.update(); } catch {}
          try {
            setInterval(() => {
              try { registration.update(); } catch {}
            }, 5 * 60 * 1000);
          } catch {}
        })
        .catch(() => {});
    } catch {}
  });
}

// Apply document direction from localStorage or ?rtl=1
try {
  const params = new URLSearchParams(window.location.search);
  const rtlParam = params.get('rtl');
  const storedDir = localStorage.getItem('dir');
  const dir = (rtlParam === '1' || rtlParam === 'true') ? 'rtl' : (storedDir || document.documentElement.getAttribute('dir') || 'ltr');
  document.documentElement.setAttribute('dir', dir);
} catch {}