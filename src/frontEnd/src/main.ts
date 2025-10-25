import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import { setupPrimeVue } from './primevue'
import App from './App.vue'
import './assets/styles/index.scss'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)
setupPrimeVue(app)

app.mount('#app')
