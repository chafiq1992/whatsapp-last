import React, { useEffect, useState } from 'react';
import api from './api';

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Prefill username for convenience; rely on the browser password manager for passwords.
  useEffect(() => {
    try {
      const saved = localStorage.getItem('agent_username') || '';
      if (saved && !username) setUsername(saved);
    } catch {}
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!username || !password) {
      setError('Please enter username and password');
      return;
    }
    setLoading(true);
    try {
      const res = await api.post('/auth/login', { username, password, token_fallback: true });
      const user = res?.data?.username || username;
      const isAdmin = !!res?.data?.is_admin;
      const accessToken = res?.data?.access_token;
      const refreshToken = res?.data?.refresh_token;
      try {
        if (user) localStorage.setItem('agent_username', user);
        localStorage.setItem('agent_is_admin', isAdmin ? '1' : '0');
        // Fallback tokens for environments that block cookies (e.g., embedded/3P contexts).
        // Prefer sessionStorage, but also mirror into localStorage as a durability fallback.
        if (accessToken) {
          sessionStorage.setItem('agent_access_token', accessToken);
          localStorage.setItem('agent_access_token', accessToken);
        }
        if (refreshToken) {
          sessionStorage.setItem('agent_refresh_token', refreshToken);
          localStorage.setItem('agent_refresh_token', refreshToken);
        }
      } catch {}
      if (typeof onSuccess === 'function') onSuccess(user, null, isAdmin);
    } catch (e) {
      const status = e?.response?.status;
      if (status === 401) {
        setError('Invalid credentials');
      } else if (status === 503 || status === 504) {
        setError('Server timeout/unavailable. Please try again.');
      } else {
        setError('Login failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-gray-900 text-white">
      <form onSubmit={handleSubmit} autoComplete="on" className="bg-gray-800 border border-gray-700 rounded-xl p-6 w-full max-w-sm space-y-4">
        <div className="text-xl font-semibold">Agent Login</div>
        {error && <div className="text-red-400 text-sm">{error}</div>}
        <div>
          <label className="block text-sm text-gray-300 mb-1">Username</label>
          <input
            name="username"
            className="w-full p-2 rounded bg-gray-900 border border-gray-700 text-white"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Password</label>
          <input
            name="password"
            type="password"
            className="w-full p-2 rounded bg-gray-900 border border-gray-700 text-white"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        <button
          type="submit"
          className={`w-full py-2 rounded bg-indigo-600 hover:bg-indigo-500 transition ${loading ? 'opacity-70 cursor-not-allowed' : ''}`}
          disabled={loading}
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}


