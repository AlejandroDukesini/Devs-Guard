import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '../index.css'
import { applyStoredTheme } from '../demo/theme.js'
import LocalApp from './LocalApp.jsx'

applyStoredTheme()

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <LocalApp />
  </StrictMode>,
)
