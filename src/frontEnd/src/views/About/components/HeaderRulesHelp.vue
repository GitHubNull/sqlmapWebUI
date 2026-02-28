<template>
  <div class="header-rules-help">
    <Accordion :multiple="true" :activeIndex="[0]">
      <AccordionPanel value="0">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-list"></i>
            <span>Header规则管理概览</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              Header规则管理提供灵活的HTTP请求头配置功能，支持持久化规则和临时会话规则：
            </p>

            <div class="rule-types">
              <Card class="rule-type-card">
                <template #title>
                  <div class="type-title">
                    <i class="pi pi-database" style="color: var(--primary-color)"></i>
                    <span>持久化规则</span>
                  </div>
                </template>
                <template #content>
                  <p>长期有效的请求头规则，存储在数据库中。支持作用域配置，可针对特定URL生效。</p>
                  <div class="feature-tags">
                    <Tag value="CRUD完整支持" severity="info" />
                    <Tag value="作用域匹配" severity="success" />
                  </div>
                </template>
              </Card>

              <Card class="rule-type-card">
                <template #title>
                  <div class="type-title">
                    <i class="pi pi-clock" style="color: var(--orange-500)"></i>
                    <span>会话Header</span>
                  </div>
                </template>
                <template #content>
                  <p>临时请求头规则，支持TTL自动过期。适合临时测试场景，如临时Token。</p>
                  <div class="feature-tags">
                    <Tag value="TTL过期" severity="warn" />
                    <Tag value="批量导入" severity="info" />
                  </div>
                </template>
              </Card>
            </div>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="1">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-database"></i>
            <span>持久化规则管理</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>创建全局规则</h4>
            <p>
              <strong>场景</strong>: 为所有扫描任务添加统一的User-Agent
            </p>
            <ol class="steps-list">
              <li>
                <strong>进入Header规则管理</strong>
                <p>在配置页面点击"Header规则"标签</p>
              </li>
              <li>
                <strong>添加规则</strong>
                <p>点击"添加规则"按钮</p>
              </li>
              <li>
                <strong>填写规则信息</strong>
                <ul>
                  <li>规则名称: <code>全局User-Agent</code></li>
                  <li>Header名称: <code>User-Agent</code></li>
                  <li>Header值: <code>Mozilla/5.0 SecurityScanner/1.0</code></li>
                  <li>替换策略: <code>完全替换</code></li>
                  <li>优先级: <code>50</code></li>
                  <li>启用规则: <code>勾选</code></li>
                  <li>配置作用域: <code>不勾选</code>（全局生效）</li>
                </ul>
              </li>
              <li>
                <strong>保存规则</strong>
                <p>点击"保存"，所有扫描任务都会使用这个User-Agent</p>
              </li>
            </ol>

            <h4>创建带作用域的规则</h4>
            <p>
              <strong>场景</strong>: 只为特定环境API添加认证Token
            </p>
            <ol class="steps-list">
              <li>点击"添加规则"</li>
              <li>
                填写规则信息:
                <ul>
                  <li>规则名称: <code>生产环境API认证</code></li>
                  <li>Header名称: <code>Authorization</code></li>
                  <li>Header值: <code>Bearer eyJhbGc...</code></li>
                  <li>优先级: <code>80</code> (高优先级)</li>
                  <li>启用规则: <code>勾选</code></li>
                  <li>配置作用域: <code>勾选</code></li>
                </ul>
              </li>
              <li>
                配置作用域匹配条件:
                <ul>
                  <li>协议匹配: <code>https</code></li>
                  <li>主机名匹配: <code>api.production.com</code></li>
                  <li>路径匹配: <code>/v1/*</code></li>
                  <li>使用正则: <code>不勾选</code></li>
                </ul>
              </li>
              <li>点击"保存"</li>
            </ol>

            <Message severity="success" :closable="false">
              <template #icon>
                <i class="pi pi-check-circle"></i>
              </template>
              结果: 只对 <code>https://api.production.com/v1/*</code> 的请求添加认证头，其他URL不受影响
            </Message>

            <h4>规则操作</h4>
            <div class="operation-grid">
              <div class="operation-item">
                <i class="pi pi-pencil"></i>
                <span><strong>编辑</strong>: 修改规则信息</span>
              </div>
              <div class="operation-item">
                <i class="pi pi-eye"></i>
                <span><strong>启用/禁用</strong>: 切换规则状态</span>
              </div>
              <div class="operation-item">
                <i class="pi pi-trash"></i>
                <span><strong>删除</strong>: 移除规则</span>
              </div>
              <div class="operation-item">
                <i class="pi pi-copy"></i>
                <span><strong>复制</strong>: 复制规则</span>
              </div>
            </div>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="2">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-sitemap"></i>
            <span>作用域配置详解</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <ScopeConfigHelp />
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="3">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-clock"></i>
            <span>会话Header管理</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>批量添加临时Headers</h4>
            <p>
              <strong>场景</strong>: 为当前测试会话添加多个临时Headers
            </p>
            <ol class="steps-list">
              <li>在配置页面点击"会话Header"标签</li>
              <li>点击"添加Header"按钮</li>
              <li>
                在文本框中输入多行Headers:
                <pre class="code-block mt-2">Authorization: Bearer temp-token-123
X-Request-ID: test-request-001
X-Custom-Header: custom-value</pre>
              </li>
              <li>
                设置参数:
                <ul>
                  <li>优先级: <code>50</code></li>
                  <li>生存时间: <code>3600</code> 秒(1小时)</li>
                </ul>
              </li>
              <li>点击"添加"</li>
            </ol>

            <Message severity="info" :closable="false">
              <template #icon>
                <i class="pi pi-info-circle"></i>
              </template>
              这些Headers将在接下来的1小时内对所有请求生效，过期后自动失效。
            </Message>

            <h4>清除会话Headers</h4>
            <p>
              点击"清除所有"按钮，确认后立即清除所有会话Headers。
            </p>

            <h4>导入功能</h4>
            <p>
              会话Header管理支持批量导入功能：
            </p>
            <ul>
              <li>从文本批量导入多行Headers</li>
              <li>支持标准HTTP Header格式</li>
              <li>自动解析Header名称和值</li>
              <li>保留替换策略设置</li>
            </ul>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="4">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-sort-amount-down"></i>
            <span>优先级与替换策略</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>优先级设置建议</h4>
            <div class="priority-table">
              <table>
                <thead>
                  <tr>
                    <th>优先级范围</th>
                    <th>建议用途</th>
                    <th>标识</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><Tag value="80-100" severity="danger" /></td>
                    <td>关键认证/授权Header</td>
                    <td><span class="priority-badge high">高优先级</span></td>
                  </tr>
                  <tr>
                    <td><Tag value="50-79" severity="warn" /></td>
                    <td>重要业务Header</td>
                    <td><span class="priority-badge medium">中优先级</span></td>
                  </tr>
                  <tr>
                    <td><Tag value="0-49" severity="info" /></td>
                    <td>一般Header</td>
                    <td><span class="priority-badge low">低优先级</span></td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h4>替换策略说明</h4>
            <div class="strategy-list">
              <div class="strategy-item">
                <Tag value="REPLACE" severity="danger" />
                <div class="strategy-detail">
                  <strong>完全替换</strong>
                  <p>完全替换原有的Header值</p>
                </div>
              </div>
              <div class="strategy-item">
                <Tag value="APPEND" severity="warn" />
                <div class="strategy-detail">
                  <strong>追加</strong>
                  <p>在原有Header值后追加内容</p>
                </div>
              </div>
              <div class="strategy-item">
                <Tag value="PREPEND" severity="info" />
                <div class="strategy-detail">
                  <strong>前置</strong>
                  <p>在原有Header值前添加内容</p>
                </div>
              </div>
              <div class="strategy-item">
                <Tag value="CONDITIONAL" severity="success" />
                <div class="strategy-detail">
                  <strong>条件替换</strong>
                  <p>满足条件时才替换Header值</p>
                </div>
              </div>
            </div>
          </div>
        </AccordionContent>
      </AccordionPanel>
    </Accordion>
  </div>
</template>

<script setup lang="ts">
import Accordion from 'primevue/accordion'
import AccordionPanel from 'primevue/accordionpanel'
import AccordionHeader from 'primevue/accordionheader'
import AccordionContent from 'primevue/accordioncontent'
import Card from 'primevue/card'
import Message from 'primevue/message'
import Tag from 'primevue/tag'
import ScopeConfigHelp from './ScopeConfigHelp.vue'
</script>

<style scoped lang="scss">
.header-rules-help {
  padding: 0.5rem 0;
}

.header-with-icon {
  display: flex;
  align-items: center;
  gap: 0.5rem;

  i {
    color: var(--primary-color);
  }
}

.help-section {
  h4 {
    margin: 1rem 0 0.5rem 0;
    color: var(--text-color);
    font-size: 1rem;

    &:first-child {
      margin-top: 0;
    }
  }

  p {
    margin: 0 0 0.75rem 0;
    color: var(--text-color-secondary);
    line-height: 1.6;
  }

  ul, ol {
    margin: 0 0 1rem 0;
    padding-left: 1.5rem;
    color: var(--text-color-secondary);

    li {
      margin-bottom: 0.4rem;
      line-height: 1.5;
    }
  }
}

.rule-types {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.rule-type-card {
  :deep(.p-card-title) {
    margin-bottom: 0.5rem;
  }

  :deep(.p-card-content) {
    padding-top: 0;

    p {
      font-size: 0.9rem;
      margin-bottom: 0.75rem;
    }
  }
}

.type-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1rem;
}

.feature-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.steps-list {
  counter-reset: step;
  list-style: none;
  padding-left: 0;

  li {
    position: relative;
    padding-left: 2.5rem;
    margin-bottom: 1rem;

    &::before {
      counter-increment: step;
      content: counter(step);
      position: absolute;
      left: 0;
      top: 0;
      width: 1.75rem;
      height: 1.75rem;
      background: var(--primary-color);
      color: white;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.85rem;
      font-weight: 600;
    }

    strong {
      color: var(--text-color);
      display: block;
      margin-bottom: 0.25rem;
    }

    p {
      margin-bottom: 0.5rem;
    }

    ul {
      margin-top: 0.5rem;
    }
  }
}

.operation-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.75rem;
  margin-top: 1rem;
}

.operation-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;

  i {
    color: var(--primary-color);
  }
}

.priority-table {
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

.strategy-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-top: 1rem;
}

.strategy-item {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 6px;
}

.strategy-detail {
  strong {
    display: block;
    color: var(--text-color);
    margin-bottom: 0.25rem;
  }

  p {
    margin: 0;
    font-size: 0.9rem;
  }
}

.priority-badge {
  display: inline-block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 600;

  &.high {
    background: var(--red-100);
    color: var(--red-700);
  }

  &.medium {
    background: var(--orange-100);
    color: var(--orange-700);
  }

  &.low {
    background: var(--blue-100);
    color: var(--blue-700);
  }
}

.mt-2 {
  margin-top: 0.5rem;
}

@media (max-width: 768px) {
  .rule-types {
    grid-template-columns: 1fr;
  }

  .operation-grid {
    grid-template-columns: 1fr;
  }

  .steps-list li {
    padding-left: 2rem;

    &::before {
      width: 1.5rem;
      height: 1.5rem;
      font-size: 0.75rem;
    }
  }

  .priority-table {
    font-size: 0.8rem;

    th, td {
      padding: 0.5rem;
    }
  }
}
</style>
