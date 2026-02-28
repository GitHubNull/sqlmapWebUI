<template>
  <div class="task-management-help">
    <Accordion :multiple="true" :activeIndex="[0]">
      <AccordionPanel value="0">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-list"></i>
            <span>任务列表功能</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              任务列表提供全面的扫描任务管理功能，支持过滤、排序、批量操作等：
            </p>

            <div class="feature-overview">
              <Card class="feature-card">
                <template #title>
                  <div class="feature-title">
                    <i class="pi pi-filter" style="color: var(--primary-color)"></i>
                    <span>多维度过滤</span>
                  </div>
                </template>
                <template #content>
                  <ul>
                    <li>URL关键字搜索</li>
                    <li>报文内容搜索</li>
                    <li>任务状态筛选</li>
                    <li>日期范围筛选</li>
                    <li>注入状态筛选</li>
                  </ul>
                </template>
              </Card>

              <Card class="feature-card">
                <template #title>
                  <div class="feature-title">
                    <i class="pi pi-sort-alt" style="color: var(--green-500)"></i>
                    <span>灵活排序</span>
                  </div>
                </template>
                <template #content>
                  <ul>
                    <li>任务ID排序</li>
                    <li>任务状态排序</li>
                    <li>创建时间排序</li>
                    <li>支持升序/降序</li>
                  </ul>
                </template>
              </Card>

              <Card class="feature-card">
                <template #title>
                  <div class="feature-title">
                    <i class="pi pi-check-square" style="color: var(--orange-500)"></i>
                    <span>批量操作</span>
                  </div>
                </template>
                <template #content>
                  <ul>
                    <li>多选/全选功能</li>
                    <li>批量停止任务</li>
                    <li>批量删除任务</li>
                    <li>删除全部任务</li>
                  </ul>
                </template>
              </Card>
            </div>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="1">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-filter"></i>
            <span>过滤功能详解</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>过滤条件说明</h4>
            <div class="filter-table">
              <table>
                <thead>
                  <tr>
                    <th>过滤类型</th>
                    <th>说明</th>
                    <th>使用方式</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>URL关键字</td>
                    <td>搜索目标URL包含的关键字</td>
                    <td>输入关键字，支持模糊匹配</td>
                  </tr>
                  <tr>
                    <td>报文关键字</td>
                    <td>搜索Headers和Body内容</td>
                    <td>输入要搜索的文本内容</td>
                  </tr>
                  <tr>
                    <td>状态筛选</td>
                    <td>按任务状态过滤</td>
                    <td>选择：等待中/运行中/已完成/失败/已停止/已终止</td>
                  </tr>
                  <tr>
                    <td>日期范围</td>
                    <td>按创建时间范围过滤</td>
                    <td>选择开始和结束日期</td>
                  </tr>
                  <tr>
                    <td>注入状态</td>
                    <td>按注入结果过滤</td>
                    <td>存在注入/无注入/未知</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h4>过滤特性</h4>
            <ul>
              <li><strong>实时过滤</strong>: 输入后300ms自动应用过滤</li>
              <li><strong>结果计数</strong>: 显示过滤后的任务数量</li>
              <li><strong>一键重置</strong>: 快速清除所有过滤条件</li>
              <li><strong>组合过滤</strong>: 多个条件可同时生效</li>
            </ul>

            <h4>使用步骤</h4>
            <ol class="steps-list">
              <li>
                <strong>打开过滤器</strong>
                <p>点击任务列表页面的"筛选"按钮展开过滤面板</p>
              </li>
              <li>
                <strong>设置过滤条件</strong>
                <p>根据需要填写或选择过滤条件</p>
              </li>
              <li>
                <strong>查看结果</strong>
                <p>表格自动更新显示过滤后的任务</p>
              </li>
              <li>
                <strong>重置过滤</strong>
                <p>点击"重置"按钮清除所有条件</p>
              </li>
            </ol>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="2">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-sort-alt"></i>
            <span>排序功能</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>可排序字段</h4>
            <div class="sort-fields">
              <div class="sort-field-item">
                <i class="pi pi-hashtag"></i>
                <span><strong>任务ID</strong>: 按任务标识符排序</span>
              </div>
              <div class="sort-field-item">
                <i class="pi pi-flag"></i>
                <span><strong>任务状态</strong>: 按状态优先级排序</span>
                <small>优先级: 运行中 > 等待中 > 失败 > 已停止 > 已完成 > 已终止</small>
              </div>
              <div class="sort-field-item">
                <i class="pi pi-calendar"></i>
                <span><strong>创建时间</strong>: 按时间戳排序</span>
              </div>
            </div>

            <h4>排序操作</h4>
            <ul>
              <li><strong>点击列头</strong>: 触发对应字段排序</li>
              <li><strong>再次点击</strong>: 切换升序/降序</li>
              <li><strong>第三次点击</strong>: 恢复默认排序</li>
              <li><strong>排序指示</strong>: 列头显示排序方向图标</li>
            </ul>

            <Message severity="info" :closable="false">
              <template #icon>
                <i class="pi pi-info-circle"></i>
              </template>
              状态排序采用自定义优先级，方便优先关注运行中和需要处理的任务。
            </Message>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="3">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-check-square"></i>
            <span>批量操作</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>多选功能</h4>
            <ul>
              <li><strong>单选</strong>: 点击行首复选框选择单个任务</li>
              <li><strong>全选</strong>: 点击表头复选框选择当前页所有任务</li>
              <li><strong>选中计数</strong>: 工具栏显示当前选中任务数量</li>
              <li><strong>安全保护</strong>: 运行中任务不能被选中删除</li>
            </ul>

            <h4>批量操作类型</h4>
            <div class="batch-operations">
              <Card class="operation-card">
                <template #title>
                  <div class="op-title">
                    <i class="pi pi-stop-circle" style="color: var(--red-500)"></i>
                    <span>批量停止</span>
                  </div>
                </template>
                <template #content>
                  <p>停止选中的运行中任务</p>
                  <small>仅对运行中任务生效</small>
                </template>
              </Card>

              <Card class="operation-card">
                <template #title>
                  <div class="op-title">
                    <i class="pi pi-trash" style="color: var(--orange-500)"></i>
                    <span>批量删除</span>
                  </div>
                </template>
                <template #content>
                  <p>删除选中的任务</p>
                  <small>运行中任务自动跳过</small>
                </template>
              </Card>

              <Card class="operation-card">
                <template #title>
                  <div class="op-title">
                    <i class="pi pi-times" style="color: var(--gray-500)"></i>
                    <span>取消选择</span>
                  </div>
                </template>
                <template #content>
                  <p>清空所有选中项</p>
                  <small>快速重置选择状态</small>
                </template>
              </Card>

              <Card class="operation-card">
                <template #title>
                  <div class="op-title">
                    <i class="pi pi-exclamation-triangle" style="color: var(--red-700)"></i>
                    <span>删除全部</span>
                  </div>
                </template>
                <template #content>
                  <p>清空所有任务</p>
                  <small>需要二次确认</small>
                </template>
              </Card>
            </div>

            <h4>安全机制</h4>
            <ul>
              <li><strong>运行中保护</strong>: 运行中任务不能被删除</li>
              <li><strong>确认对话框</strong>: 删除操作需确认</li>
              <li><strong>二次确认</strong>: 删除全部需输入确认文本</li>
              <li><strong>数量限制</strong>: 单次最多删除100个任务</li>
            </ul>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="4">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-chart-bar"></i>
            <span>汇总统计</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              任务列表表格底部显示实时统计行，包含以下信息：
            </p>
            <ul>
              <li><strong>总任务数</strong>: 当前显示的任务总数</li>
              <li><strong>可注入任务数</strong>: 发现SQL注入漏洞的任务数量</li>
              <li><strong>状态分布</strong>: 各状态任务的数量统计</li>
            </ul>
            <p>
              统计行会随过滤条件实时更新，方便了解当前视图的数据概况。
            </p>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="5">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-bolt"></i>
            <span>智能轮询与通知</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>智能轮询策略</h4>
            <p>
              系统采用智能轮询机制，自动调整刷新频率：
            </p>
            <ul>
              <li><strong>自动启动</strong>: 有运行中任务时自动启动轮询</li>
              <li><strong>自动停止</strong>: 无运行中任务时自动停止轮询</li>
              <li><strong>页面感知</strong>: 页面隐藏时暂停，显示时恢复</li>
              <li><strong>间隔可调</strong>: 在配置页面调整刷新间隔(1-60分钟)</li>
            </ul>

            <h4>WebSocket实时通知</h4>
            <p>
              系统支持WebSocket实时通知机制：
            </p>
            <ul>
              <li><strong>状态变更推送</strong>: 任务状态变化时主动推送</li>
              <li><strong>新任务通知</strong>: 新任务创建时自动通知</li>
              <li><strong>即时反馈</strong>: 减少不必要的轮询请求</li>
            </ul>

            <h4>配置刷新间隔</h4>
            <ol class="steps-list">
              <li>进入"配置"页面</li>
              <li>在"系统配置"Tab中找到刷新间隔设置</li>
              <li>拖动滑块选择间隔时间(1-60分钟)</li>
              <li>滑块带有刻度标记，主刻度每5分钟，次刻度每1分钟</li>
              <li>设置自动保存</li>
            </ol>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="6">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-exclamation-circle"></i>
            <span>操作确认</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              为防止误操作，以下操作需要确认：
            </p>
            <div class="confirm-list">
              <div class="confirm-item">
                <i class="pi pi-trash"></i>
                <span>删除单个任务</span>
              </div>
              <div class="confirm-item">
                <i class="pi pi-stop-circle"></i>
                <span>停止单个任务</span>
              </div>
              <div class="confirm-item">
                <i class="pi pi-trash"></i>
                <span>批量删除任务</span>
              </div>
              <div class="confirm-item">
                <i class="pi pi-stop-circle"></i>
                <span>批量停止任务</span>
              </div>
              <div class="confirm-item">
                <i class="pi pi-exclamation-triangle"></i>
                <span>删除全部任务（需二次确认）</span>
              </div>
            </div>

            <Message severity="warn" :closable="false">
              <template #icon>
                <i class="pi pi-exclamation-triangle"></i>
              </template>
              删除操作不可恢复，请谨慎操作！
            </Message>
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
</script>

<style scoped lang="scss">
.task-management-help {
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

.feature-overview {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.feature-card {
  :deep(.p-card-title) {
    margin-bottom: 0.5rem;
  }

  :deep(.p-card-content) {
    padding-top: 0;

    ul {
      margin: 0;
      padding-left: 1.25rem;
      font-size: 0.9rem;

      li {
        margin-bottom: 0.3rem;
      }
    }
  }
}

.feature-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1rem;
}

.filter-table {
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

.sort-fields {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin: 1rem 0;
}

.sort-field-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;

  i {
    color: var(--primary-color);
    margin-right: 0.5rem;
  }

  small {
    color: var(--text-color-secondary);
    font-size: 0.85rem;
    margin-left: 1.5rem;
  }
}

.batch-operations {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.75rem;
  margin: 1rem 0;
}

.operation-card {
  :deep(.p-card-title) {
    margin-bottom: 0.25rem;
  }

  :deep(.p-card-content) {
    padding-top: 0;

    p {
      margin: 0 0 0.25rem 0;
      font-size: 0.9rem;
    }

    small {
      color: var(--text-color-secondary);
      font-size: 0.8rem;
    }
  }
}

.op-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.95rem;
}

.confirm-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin: 1rem 0;
}

.confirm-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;

  i {
    color: var(--orange-500);
  }
}

@media (max-width: 768px) {
  .feature-overview,
  .batch-operations {
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

  .filter-table {
    font-size: 0.8rem;

    th, td {
      padding: 0.5rem;
    }
  }
}
</style>
