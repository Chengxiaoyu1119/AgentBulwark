import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { setAuthTokenProvider } from './api';
import './design/tokens.css';
import './styles.css';
import './视觉系统.css';

const configuredApiToken = import.meta.env.VITE_AGENT_SUPERVISOR_API_TOKEN?.trim();

setAuthTokenProvider(() => {
  if (configuredApiToken) {
    return configuredApiToken;
  }
  try {
    return (
      window.sessionStorage.getItem('agent-supervisor-api-token') ||
      window.localStorage.getItem('agent-supervisor-api-token')
    );
  } catch {
    return null;
  }
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
