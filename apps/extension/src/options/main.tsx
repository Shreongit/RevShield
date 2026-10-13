import React from 'react';
import ReactDOM from 'react-dom/client';
import { Options } from './Options';
import '../styles/index.css';

ReactDOM.createRoot(document.getElementById('options-root')!).render(
  <React.StrictMode>
    <Options />
  </React.StrictMode>
);
