<script setup lang="ts">
import { onMounted } from 'vue'
import { useAuthStore } from './stores/auth'
import { initToast } from './api/request'
import Toast from 'primevue/toast'
import ConfirmDialog from 'primevue/confirmdialog'
import ConfirmPopup from 'primevue/confirmpopup'
import OfflineBanner from './components/OfflineBanner.vue'

const authStore = useAuthStore()

// 初始化Toast实例（必须在setup中调用useToast）
initToast()

onMounted(() => {
  authStore.initAuth()
})
</script>

<template>
  <Toast position="top-right" />
  <ConfirmDialog />
    <ConfirmPopup group="popup" />
  <OfflineBanner />
  <router-view />
</template>

<style>
#app {
  min-height: 100vh;
}
</style>
