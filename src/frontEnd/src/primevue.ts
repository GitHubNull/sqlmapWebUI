import type { App } from 'vue'
import PrimeVue from 'primevue/config'
import Aura from '@primevue/themes/aura'
import { definePreset } from '@primevue/themes'
import Tooltip from 'primevue/tooltip'
import ToastService from 'primevue/toastservice'
import ConfirmationService from 'primevue/confirmationservice'

// 导入 PrimeIcons
import 'primeicons/primeicons.css'

// 自定义主题预设 - 添加语义化的 surface 变量
const SqlmapWebUIPreset = definePreset(Aura, {
  semantic: {
    colorScheme: {
      light: {
        surface: {
          ground: '{surface.50}',
          card: '{surface.0}',
          section: '{surface.100}',
          border: '{surface.200}'
        },
        text: {
          secondaryColor: '{zinc.600}'
        }
      },
      dark: {
        surface: {
          ground: '{surface.950}',
          card: '{surface.900}',
          section: '{surface.800}',
          border: '{surface.700}'
        },
        text: {
          secondaryColor: '{zinc.400}'
        }
      }
    }
  },
  components: {
    datepicker: {
      colorScheme: {
        light: {
          panel: {
            background: '{surface.0}',
            borderColor: '{surface.200}',
            color: '{surface.700}'
          },
          header: {
            background: '{surface.0}',
            borderColor: '{surface.200}',
            color: '{surface.700}'
          },
          date: {
            color: '{surface.700}'
          }
        },
        dark: {
          panel: {
            background: '{surface.900}',
            borderColor: '{surface.700}',
            color: '{surface.0}'
          },
          header: {
            background: '{surface.900}',
            borderColor: '{surface.700}',
            color: '{surface.0}'
          },
          date: {
            color: '{surface.0}'
          }
        }
      }
    },
    select: {
      colorScheme: {
        light: {
          overlay: {
            background: '{surface.0}',
            borderColor: '{surface.200}',
            color: '{surface.700}'
          },
          option: {
            color: '{surface.700}',
            focusBackground: '{surface.100}',
            selectedBackground: '{primary.color}',
            selectedColor: '{primary.contrast.color}'
          }
        },
        dark: {
          overlay: {
            background: '{surface.900}',
            borderColor: '{surface.700}',
            color: '{surface.0}'
          },
          option: {
            color: '{surface.0}',
            focusBackground: '{surface.800}',
            selectedBackground: '{primary.color}',
            selectedColor: '{primary.contrast.color}'
          }
        }
      }
    },
    multiselect: {
      colorScheme: {
        light: {
          overlay: {
            background: '{surface.0}',
            borderColor: '{surface.200}',
            color: '{surface.700}'
          },
          option: {
            color: '{surface.700}',
            focusBackground: '{surface.100}'
          }
        },
        dark: {
          overlay: {
            background: '{surface.900}',
            borderColor: '{surface.700}',
            color: '{surface.0}'
          },
          option: {
            color: '{surface.0}',
            focusBackground: '{surface.800}'
          }
        }
      }
    },
    dropdown: {
      colorScheme: {
        light: {
          overlay: {
            background: '{surface.0}',
            borderColor: '{surface.200}',
            color: '{surface.700}'
          },
          option: {
            color: '{surface.700}',
            focusBackground: '{surface.100}'
          }
        },
        dark: {
          overlay: {
            background: '{surface.900}',
            borderColor: '{surface.700}',
            color: '{surface.0}'
          },
          option: {
            color: '{surface.0}',
            focusBackground: '{surface.800}'
          }
        }
      }
    },
    dialog: {
      colorScheme: {
        light: {
          background: '{surface.0}',
          borderColor: '{surface.200}',
          color: '{surface.700}'
        },
        dark: {
          background: '{surface.900}',
          borderColor: '{surface.700}',
          color: '{surface.0}'
        }
      }
    },
    datatable: {
      colorScheme: {
        light: {
          header: {
            cell: {
              background: '{surface.100}',
              borderColor: '{surface.200}',
              color: '{surface.700}'
            }
          },
          row: {
            background: '{surface.0}',
            hoverBackground: '{surface.100}',
            color: '{surface.700}'
          },
          body: {
            cell: {
              borderColor: '{surface.200}'
            }
          }
        },
        dark: {
          header: {
            cell: {
              background: '{surface.800}',
              borderColor: '{surface.700}',
              color: '{surface.0}'
            }
          },
          row: {
            background: '{surface.900}',
            hoverBackground: '{surface.800}',
            color: '{surface.0}'
          },
          body: {
            cell: {
              borderColor: '{surface.700}'
            }
          }
        }
      }
    }
  }
})

export function setupPrimeVue(app: App) {
  app.use(PrimeVue, {
    theme: {
      preset: SqlmapWebUIPreset,
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
