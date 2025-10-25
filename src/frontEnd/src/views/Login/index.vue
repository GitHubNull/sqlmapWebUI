<template>
  <div class="login-page">
    <Card class="login-card">
      <template #title>
        <div class="login-title">
          <i class="pi pi-shield" style="font-size: 2rem; color: #3B82F6;"></i>
          <h2>SqlmapWebUI</h2>
        </div>
      </template>
      <template #content>
        <div class="login-form">
          <div class="field">
            <label for="username">用户名</label>
            <InputText id="username" v-model="formData.username" placeholder="请输入用户名" />
          </div>
          <div class="field">
            <label for="password">密码</label>
            <Password id="password" v-model="formData.password" placeholder="请输入密码" :feedback="false" toggleMask />
          </div>
          <Button label="登录" icon="pi pi-sign-in" @click="handleLogin" :loading="loading" class="w-full" />
        </div>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const formData = reactive({
  username: '',
  password: '',
})

const loading = ref(false)

async function handleLogin() {
  loading.value = true
  try {
    await authStore.login(formData)
    const redirect = (route.query.redirect as string) || '/home'
    router.push(redirect)
  } catch (error) {
    console.error('Login failed:', error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped lang="scss">
.login-page {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.login-card {
  width: 100%;
  max-width: 400px;
}

.login-title {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.w-full {
  width: 100%;
}
</style>
