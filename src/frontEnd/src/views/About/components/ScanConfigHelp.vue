<template>
  <div class="scan-config-help">
    <Accordion :multiple="true" :activeIndex="[0]">
      <AccordionPanel value="0">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-sliders-h"></i>
            <span>扫描配置管理概览</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              扫描配置管理提供三种配置类型，满足不同场景下的扫描需求：
            </p>

            <div class="config-types">
              <Card class="config-type-card">
                <template #title>
                  <div class="type-title">
                    <i class="pi pi-star-fill" style="color: var(--primary-color)"></i>
                    <span>默认配置</span>
                  </div>
                </template>
                <template #content>
                  <p>全局默认扫描参数，新建任务时自动应用。适合大多数扫描任务使用相同参数的场景。</p>
                  <Tag value="全局生效" severity="info" class="mt-2" />
                </template>
              </Card>

              <Card class="config-type-card">
                <template #title>
                  <div class="type-title">
                    <i class="pi pi-bookmark-fill" style="color: var(--green-500)"></i>
                    <span>常用配置</span>
                  </div>
                </template>
                <template #content>
                  <p>保存常用的配置组合，支持完整的增删改查操作。针对特定场景（如MySQL深度扫描）保存专用配置。</p>
                  <Tag value="自定义保存" severity="success" class="mt-2" />
                </template>
              </Card>

              <Card class="config-type-card">
                <template #title>
                  <div class="type-title">
                    <i class="pi pi-history" style="color: var(--orange-500)"></i>
                    <span>历史配置</span>
                  </div>
                </template>
                <template #content>
                  <p>自动记录历史扫描使用过的配置，支持排序和分页。方便复用之前的扫描参数。</p>
                  <Tag value="自动记录" severity="warn" class="mt-2" />
                </template>
              </Card>
            </div>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="1">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-star"></i>
            <span>默认配置设置</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>配置步骤</h4>
            <ol class="steps-list">
              <li>
                <strong>进入配置页面</strong>
                <p>点击导航栏"配置"菜单，进入配置管理页面</p>
              </li>
              <li>
                <strong>选择扫描配置Tab</strong>
                <p>点击"扫描配置"标签页，切换到配置管理界面</p>
              </li>
              <li>
                <strong>设置默认配置</strong>
                <p>在"默认配置"面板中设置全局默认参数：</p>
                <ul>
                  <li>检测等级(Level): 1-5</li>
                  <li>风险等级(Risk): 1-3</li>
                  <li>数据库类型(DBMS): 自动检测或指定</li>
                  <li>注入技术(Technique): BEUSTQ组合</li>
                  <li>其他SQLMap参数</li>
                </ul>
              </li>
              <li>
                <strong>保存配置</strong>
                <p>点击"保存"按钮，配置将自动应用到所有新建任务</p>
              </li>
            </ol>

            <Message severity="info" :closable="false">
              <template #icon>
                <i class="pi pi-info-circle"></i>
              </template>
              默认配置会在创建新任务时自动填充，但可以在任务创建页面手动修改。
            </Message>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="2">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-bookmark"></i>
            <span>常用配置管理</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>创建常用配置</h4>
            <ol class="steps-list">
              <li>
                <strong>进入常用配置面板</strong>
                <p>在扫描配置页面点击"常用配置"标签</p>
              </li>
              <li>
                <strong>添加配置</strong>
                <p>点击"添加配置"按钮，选择配置方式：</p>
                <ul>
                  <li><strong>直接添加</strong>: 手动输入配置名称和参数</li>
                  <li><strong>引导式添加</strong>: 使用可视化界面配置参数</li>
                </ul>
              </li>
              <li>
                <strong>填写配置信息</strong>
                <ul>
                  <li>配置名称：如"MySQL深度扫描"、"快速检测"</li>
                  <li>配置描述（可选）：说明配置适用场景</li>
                  <li>SQLMap参数：完整命令行参数</li>
                </ul>
              </li>
              <li>
                <strong>保存配置</strong>
                <p>点击"保存"，配置将显示在常用配置列表中</p>
              </li>
            </ol>

            <h4>引导式参数编辑器</h4>
            <p>
              引导式编辑器提供可视化界面配置SQLMap参数，无需记忆命令行语法：
            </p>
            <ul>
              <li>通过下拉菜单选择参数值</li>
              <li>复选框启用/禁用特定功能</li>
              <li>实时预览生成的命令行参数</li>
              <li>自动验证参数组合合法性</li>
            </ul>

            <h4>管理常用配置</h4>
            <div class="feature-list">
              <div class="feature-item">
                <i class="pi pi-pencil"></i>
                <span><strong>编辑</strong>: 修改已有配置的参数</span>
              </div>
              <div class="feature-item">
                <i class="pi pi-copy"></i>
                <span><strong>复制</strong>: 基于现有配置创建新配置</span>
              </div>
              <div class="feature-item">
                <i class="pi pi-trash"></i>
                <span><strong>删除</strong>: 移除不再需要的配置</span>
              </div>
              <div class="feature-item">
                <i class="pi pi-check-circle"></i>
                <span><strong>使用</strong>: 在创建任务时快速应用</span>
              </div>
            </div>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="3">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-history"></i>
            <span>历史配置功能</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>功能特性</h4>
            <p>
              历史配置自动记录每次扫描使用的参数组合，方便后续复用：
            </p>
            <ul>
              <li><strong>自动记录</strong>: 每次创建任务自动保存配置</li>
              <li><strong>智能去重</strong>: 相同配置只更新使用时间</li>
              <li><strong>使用计数</strong>: 显示每个配置的使用次数</li>
              <li><strong>排序功能</strong>: 支持按ID、参数、时间、次数排序</li>
              <li><strong>分页显示</strong>: 支持选择每页显示数量</li>
            </ul>

            <h4>使用历史配置</h4>
            <ol class="steps-list">
              <li>在扫描配置页面点击"历史配置"标签</li>
              <li>浏览历史配置列表，查看参数详情</li>
              <li>点击"使用"按钮快速应用该配置</li>
              <li>或点击"保存为常用"将历史配置转为常用配置</li>
            </ol>

            <h4>Burp插件集成</h4>
            <p>
              通过Burp Suite插件发送的请求也会自动保存到历史配置：
            </p>
            <ul>
              <li>右键发送请求后自动记录配置</li>
              <li>历史配置表格自动刷新</li>
              <li>可在Web界面查看和管理</li>
            </ul>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="4">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-eye"></i>
            <span>命令行预览</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              命令行预览组件采用<strong>GitHub Dark主题风格</strong>，提供终端窗口样式的参数预览：
            </p>
            <ul>
              <li>实时显示生成的SQLMap命令行</li>
              <li>语法高亮显示参数和值</li>
              <li>支持一键复制命令</li>
              <li>暗色/亮色主题自适应</li>
            </ul>

            <h4>预览示例</h4>
            <div class="preview-example">
              <div class="terminal-header">
                <span class="terminal-dot red"></span>
                <span class="terminal-dot yellow"></span>
                <span class="terminal-dot green"></span>
                <span class="terminal-title">Command Preview</span>
              </div>
              <pre class="terminal-content"><code>python sqlmap.py -r request.txt --batch --level=3 --risk=2 --technique=BEUST --threads=5</code></pre>
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
</script>

<style scoped lang="scss">
.scan-config-help {
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

.config-types {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.config-type-card {
  :deep(.p-card-title) {
    margin-bottom: 0.5rem;
  }

  :deep(.p-card-content) {
    padding-top: 0;

    p {
      font-size: 0.9rem;
      margin-bottom: 0.5rem;
    }
  }
}

.type-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1rem;
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

.feature-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.75rem;
  margin-top: 1rem;
}

.feature-item {
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

.mt-2 {
  margin-top: 0.5rem;
}

.preview-example {
  margin-top: 1rem;
  border-radius: 8px;
  overflow: hidden;
  background: #0d1117;
  border: 1px solid #30363d;
}

.terminal-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: #161b22;
  border-bottom: 1px solid #30363d;
}

.terminal-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;

  &.red {
    background: #ff5f56;
  }

  &.yellow {
    background: #ffbd2e;
  }

  &.green {
    background: #27c93f;
  }
}

.terminal-title {
  margin-left: 0.5rem;
  font-size: 0.8rem;
  color: #8b949e;
}

.terminal-content {
  padding: 1rem;
  margin: 0;
  font-family: 'Consolas', 'Monaco', 'SF Mono', monospace;
  font-size: 0.85rem;
  line-height: 1.5;
  color: #e6edf3;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

@media (max-width: 768px) {
  .config-types {
    grid-template-columns: 1fr;
  }

  .feature-list {
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
}
</style>
