<template>
  <div class="scope-config-help">
    <h4>作用域字段说明</h4>
    <div class="scope-table">
      <table>
        <thead>
          <tr>
            <th>字段</th>
            <th>说明</th>
            <th>示例</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>协议匹配</td>
            <td>匹配http或https</td>
            <td><code>https</code> 或 <code>http,https</code></td>
          </tr>
          <tr>
            <td>主机名匹配</td>
            <td>匹配域名(支持通配符*)</td>
            <td><code>*.example.com</code></td>
          </tr>
          <tr>
            <td>IP匹配</td>
            <td>匹配IP地址(支持通配符*)</td>
            <td><code>192.168.1.*</code></td>
          </tr>
          <tr>
            <td>端口匹配</td>
            <td>匹配端口号(支持多个)</td>
            <td><code>80,443,8080</code></td>
          </tr>
          <tr>
            <td>路径匹配</td>
            <td>匹配URL路径(支持通配符*)</td>
            <td><code>/api/*</code></td>
          </tr>
          <tr>
            <td>使用正则</td>
            <td>启用正则表达式匹配</td>
            <td>勾选/不勾选</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h4>匹配逻辑</h4>
    <ul>
      <li><strong>不填写作用域</strong>: 全局生效，匹配所有URL</li>
      <li><strong>填写作用域</strong>: 所有配置项都必须匹配才生效(AND逻辑)</li>
      <li><strong>字段留空</strong>: 该维度不限制(等同于通配符)</li>
    </ul>

    <h4>作用域示例</h4>
    <div class="example-cards">
      <Card class="example-card">
        <template #title>
          <Tag value="示例1" severity="info" />
          <span class="example-title">只匹配HTTPS</span>
        </template>
        <template #content>
          <pre class="code-block">{
  "protocol_pattern": "https"
}</pre>
          <p class="match-result">
            <i class="pi pi-check" style="color: var(--green-500)"></i> 匹配: <code>https://任何域名/任何路径</code><br>
            <i class="pi pi-times" style="color: var(--red-500)"></i> 不匹配: <code>http://...</code>
          </p>
        </template>
      </Card>

      <Card class="example-card">
        <template #title>
          <Tag value="示例2" severity="info" />
          <span class="example-title">匹配子域名</span>
        </template>
        <template #content>
          <pre class="code-block">{
  "host_pattern": "*.example.com"
}</pre>
          <p class="match-result">
            <i class="pi pi-check" style="color: var(--green-500)"></i> 匹配: <code>api.example.com</code>, <code>www.example.com</code><br>
            <i class="pi pi-times" style="color: var(--red-500)"></i> 不匹配: <code>example.com</code>
          </p>
        </template>
      </Card>

      <Card class="example-card">
        <template #title>
          <Tag value="示例3" severity="info" />
          <span class="example-title">匹配特定API</span>
        </template>
        <template #content>
          <pre class="code-block">{
  "protocol_pattern": "https",
  "host_pattern": "api.production.com",
  "path_pattern": "/v1/*"
}</pre>
          <p class="match-result">
            <i class="pi pi-check" style="color: var(--green-500)"></i> 匹配: <code>https://api.production.com/v1/users</code><br>
            <i class="pi pi-times" style="color: var(--red-500)"></i> 不匹配: <code>http://...</code> (协议不匹配)
          </p>
        </template>
      </Card>
    </div>
  </div>
</template>

<script setup lang="ts">
import Card from 'primevue/card'
import Tag from 'primevue/tag'
</script>

<style scoped lang="scss">
.scope-config-help {
  h4 {
    margin: 1rem 0 0.5rem 0;
    color: var(--text-color);
    font-size: 1rem;

    &:first-child {
      margin-top: 0;
    }
  }

  ul {
    margin: 0 0 1rem 0;
    padding-left: 1.5rem;
    color: var(--text-color-secondary);

    li {
      margin-bottom: 0.4rem;
      line-height: 1.5;
    }
  }
}

.scope-table {
  overflow-x: auto;
  margin: 1rem 0;

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;

    th, td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid var(--surface-border);
    }

    th {
      background: var(--surface-ground);
      font-weight: 600;
      color: var(--text-color);
    }

    td {
      color: var(--text-color-secondary);

      code {
        background: var(--surface-ground);
        padding: 0.2rem 0.4rem;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.85rem;
      }
    }

    tr:hover td {
      background: var(--surface-hover);
    }
  }
}

.example-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.example-card {
  :deep(.p-card-title) {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
    font-size: 0.95rem;
  }
}

.example-title {
  font-weight: 600;
}

.code-block {
  background: var(--surface-ground);
  border-radius: 6px;
  padding: 0.75rem;
  margin: 0 0 0.75rem 0;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.8rem;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text-color);
}

.match-result {
  font-size: 0.85rem;
  line-height: 1.8;

  i {
    margin-right: 0.25rem;
  }
}

@media (max-width: 768px) {
  .example-cards {
    grid-template-columns: 1fr;
  }

  .scope-table {
    font-size: 0.8rem;

    th, td {
      padding: 0.5rem;
    }
  }
}
</style>
