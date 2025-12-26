import type { App } from 'vue'
import PrimeVue from 'primevue/config'
import Lara from '@primevue/themes/lara'
import Tooltip from 'primevue/tooltip'
import ToastService from 'primevue/toastservice'
import ConfirmationService from 'primevue/confirmationservice'
import Select from 'primevue/select'
import ToggleSwitch from 'primevue/toggleswitch'

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
  
  // 注册ToastService
  app.use(ToastService)
  
  // 注册ConfirmationService
  app.use(ConfirmationService)
  
  // 注册Tooltip指令
  app.directive('tooltip', Tooltip)
  
  // 显式注册Select组件(解决PrimeVueResolver未自动识别问题)
  app.component('Select', Select)
  app.component('ToggleSwitch', ToggleSwitch)
}
