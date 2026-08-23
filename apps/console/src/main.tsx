import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { setAuthTokenProvider } from './api';
import { getAuthToken } from './app/authSession';
import './design/tokens.css';
import './styles.css';
import './视觉系统.css';

setAuthTokenProvider(getAuthToken);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
