<template>
  <div class="vulnshop-help">
    <p>
      VulnShop是内置的SQL注入漏洞测试靶场，模拟电商平台环境。
    </p>

    <h4>漏洞类型</h4>
    <div class="vuln-types">
      <div class="vuln-item">
        <Tag value="Error-based" severity="danger" />
        <span>基于错误的注入</span>
        <small>POST /api/user/login</small>
      </div>
      <div class="vuln-item">
        <Tag value="Union-based" severity="danger" />
        <span>联合查询注入</span>
        <small>GET /api/user/profile</small>
      </div>
      <div class="vuln-item">
        <Tag value="Boolean-blind" severity="warn" />
        <span>布尔盲注</span>
        <small>GET /api/products/search</small>
      </div>
      <div class="vuln-item">
        <Tag value="Time-based" severity="warn" />
        <span>时间盲注</span>
        <small>GET /api/products/detail</small>
      </div>
      <div class="vuln-item">
        <Tag value="Stacked" severity="info" />
        <span>堆叠查询注入</span>
        <small>GET /api/orders/query</small>
      </div>
      <div class="vuln-item">
        <Tag value="2nd Order" severity="secondary" />
        <span>二次注入</span>
        <small>POST /api/user/register</small>
      </div>
    </div>

    <h4>难度级别</h4>
    <div class="difficulty-levels">
      <div class="difficulty-item easy">
        <Tag value="Easy" severity="success" />
        <span>无WAF防护，直接注入</span>
      </div>
      <div class="difficulty-item medium">
        <Tag value="Medium" severity="warn" />
        <span>简单过滤，需大小写/编码绕过</span>
      </div>
      <div class="difficulty-item hard">
        <Tag value="Hard" severity="danger" />
        <span>严格过滤，需高级绕过技术</span>
      </div>
    </div>

    <h4>测试账户</h4>
    <div class="test-accounts">
      <table>
        <thead>
          <tr>
            <th>用户名</th>
            <th>密码</th>
            <th>角色</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>admin</code></td>
            <td><code>admin123</code></td>
            <td>管理员</td>
          </tr>
          <tr>
            <td><code>test</code></td>
            <td><code>test</code></td>
            <td>普通用户</td>
          </tr>
        </tbody>
      </table>
    </div>

    <Message severity="warn" :closable="false">
      <template #icon>
        <i class="pi pi-exclamation-triangle"></i>
      </template>
      VulnShop靶场仅绑定127.0.0.1，禁止暴露到公网！
    </Message>
  </div>
</template>

<script setup lang="ts">
import Message from 'primevue/message'
import Tag from 'primevue/tag'
</script>

<style scoped lang="scss">
.vulnshop-help {
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

.vuln-types {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin: 1rem 0;
}

.vuln-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;

  span {
    flex: 1;
  }

  small {
    color: var(--text-color-secondary);
    font-family: monospace;
    font-size: 0.85rem;
  }
}

.difficulty-levels {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin: 1rem 0;
}

.difficulty-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;

  &.easy {
    border-left: 3px solid var(--green-500);
  }

  &.medium {
    border-left: 3px solid var(--orange-500);
  }

  &.hard {
    border-left: 3px solid var(--red-500);
  }
}

.test-accounts {
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

@media (max-width: 768px) {
  .vuln-item {
    flex-wrap: wrap;

    small {
      width: 100%;
      margin-top: 0.25rem;
    }
  }

  .test-accounts {
    font-size: 0.8rem;

    th, td {
      padding: 0.5rem;
    }
  }
}
</style>
