<template>
  <div class="sqlmap-params-help">
    <p>
      本项目支持SQLMap的<strong>215个参数</strong>（除<code>-r</code>外），完全兼容SQLMap 1.9.11.3+。
    </p>

    <h4>参数分类总览</h4>
    <div class="category-grid">
      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-target" style="color: var(--red-500)"></i>
            <span>Target</span>
            <Tag value="8" severity="danger" />
          </div>
        </template>
        <template #content>
          <p>目标定义（URL、日志、批量文件等）</p>
        </template>
      </Card>

      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-send" style="color: var(--blue-500)"></i>
            <span>Request</span>
            <Tag value="51" severity="info" />
          </div>
        </template>
        <template #content>
          <p>HTTP请求配置（认证、代理、CSRF等）</p>
        </template>
      </Card>

      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-bolt" style="color: var(--yellow-500)"></i>
            <span>Optimization</span>
            <Tag value="5" severity="warn" />
          </div>
        </template>
        <template #content>
          <p>性能优化（线程、连接等）</p>
        </template>
      </Card>

      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-syringe" style="color: var(--purple-500)"></i>
            <span>Injection</span>
            <Tag value="17" severity="secondary" />
          </div>
        </template>
        <template #content>
          <p>注入测试配置（测试参数、注入技术等）</p>
        </template>
      </Card>

      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-search" style="color: var(--green-500)"></i>
            <span>Detection</span>
            <Tag value="8" severity="success" />
          </div>
        </template>
        <template #content>
          <p>检测配置（level、risk、匹配规则等）</p>
        </template>
      </Card>

      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-cog" style="color: var(--cyan-500)"></i>
            <span>Techniques</span>
            <Tag value="9" />
          </div>
        </template>
        <template #content>
          <p>注入技术配置（UNION、DNS外泄等）</p>
        </template>
      </Card>

      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-database" style="color: var(--pink-500)"></i>
            <span>Enumeration</span>
            <Tag value="36" severity="danger" />
          </div>
        </template>
        <template #content>
          <p>数据枚举（表、列、用户等）</p>
        </template>
      </Card>

      <Card class="category-card">
        <template #title>
          <div class="category-title">
            <i class="pi pi-shield" style="color: var(--orange-500)"></i>
            <span>OS Takeover</span>
            <Tag value="8" severity="warn" />
          </div>
        </template>
        <template #content>
          <p>操作系统接管（命令执行、shell等）</p>
        </template>
      </Card>
    </div>

    <Message severity="info" :closable="false">
      <template #icon>
        <i class="pi pi-info-circle"></i>
      </template>
      完整参数列表请参阅项目文档 <code>doc/SQLMap参数支持进度.md</code>
    </Message>
  </div>
</template>

<script setup lang="ts">
import Card from 'primevue/card'
import Message from 'primevue/message'
import Tag from 'primevue/tag'
</script>

<style scoped lang="scss">
.sqlmap-params-help {
  p {
    margin: 0 0 0.75rem 0;
    color: var(--text-color-secondary);
    line-height: 1.6;
  }

  h4 {
    margin: 1rem 0 0.5rem 0;
    color: var(--text-color);
    font-size: 1rem;
  }
}

.category-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.75rem;
  margin: 1rem 0;
}

.category-card {
  :deep(.p-card-title) {
    margin-bottom: 0.25rem;
  }

  :deep(.p-card-content) {
    padding-top: 0;

    p {
      margin: 0;
      font-size: 0.85rem;
    }
  }
}

.category-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.95rem;

  .p-tag {
    margin-left: auto;
  }
}

@media (max-width: 768px) {
  .category-grid {
    grid-template-columns: 1fr;
  }
}
</style>
