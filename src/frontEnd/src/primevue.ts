import type { App } from 'vue'
import PrimeVue from 'primevue/config'
import Aura from '@primevue/themes/aura'
import Tooltip from 'primevue/tooltip'
import ToastService from 'primevue/toastservice'
import ConfirmationService from 'primevue/confirmationservice'

// 导入 PrimeIcons
import 'primeicons/primeicons.css'

export function setupPrimeVue(app: App) {
  app.use(PrimeVue, {
    theme: {
      preset: Aura,
      options: {
        prefix: 'p',
        darkModeSelector: '.app-dark',
        cssLayer: false
      }
    },
    ripple: true,
    inputStyle: 'outlined'
  })

  // 注册服务
  app.use(ToastService)
  app.use(ConfirmationService)

  // 注册指令
  app.directive('tooltip', Tooltip)
}
