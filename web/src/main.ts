import { createApp } from 'vue'

import App from './App.vue'
import './ui/styles.css'
import { initializeLocale } from './ui/i18n'
import { initializeTheme } from './ui/preferences'

initializeLocale()
initializeTheme()

createApp(App).mount('#app')
