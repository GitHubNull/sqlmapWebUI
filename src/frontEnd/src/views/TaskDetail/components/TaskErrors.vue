<template>
  <div class="errors-container">
    <Message
      v-for="(error, index) in errors"
      :key="index"
      severity="error"
      :closable="false"
    >
      {{ error }}
    </Message>
  </div>
</template>

<script setup lang="ts">
interface Props {
  errors: string[]
}

const props = defineProps<Props>()
</script>

<style scoped lang="scss">
.errors-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
</style>