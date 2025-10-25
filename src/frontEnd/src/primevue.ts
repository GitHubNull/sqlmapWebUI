import type { App } from 'vue'
import PrimeVue from 'primevue/config'
import Lara from '@primevue/themes/lara'

// 导入PrimeIcons图标库CSS(使用直接路径)
import 'primeicons/primeicons.css'

export function setupPrimeVue(app: App) {
  app.use(PrimeVue, {
    theme: {
      preset: Lara,
      options: {
        darkModeSelector: '.dark-mode',
        cssLayer: {
          name: 'primevue',
          order: 'tailwind-base, primevue, tailwind-utilities'
        }
      }
    },
    ripple: true,
    inputStyle: 'outlined',
  })
}
