<template>
  <div class="advanced-features-help">
    <Accordion :multiple="true" :activeIndex="[0]">
      <AccordionPanel value="0">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-code"></i>
            <span>SQLMap参数完整支持</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <SqlMapParamsHelp />
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="1">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-file-edit"></i>
            <span>HTTP代码编辑器</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              内置代码编辑器提供专业的HTTP请求编辑体验：
            </p>

            <div class="editor-features">
              <div class="editor-feature">
                <i class="pi pi-list"></i>
                <div class="feature-detail">
                  <strong>行号显示</strong>
                  <p>清晰的行号标识，方便定位</p>
                </div>
              </div>
              <div class="editor-feature">
                <i class="pi pi-palette"></i>
                <div class="feature-detail">
                  <strong>语法高亮</strong>
                  <p>HTTP语法着色，提高可读性</p>
                </div>
              </div>
              <div class="editor-feature">
                <i class="pi pi-search"></i>
                <div class="feature-detail">
                  <strong>搜索功能</strong>
                  <p>快捷键Ctrl+F快速搜索</p>
                </div>
              </div>
              <div class="editor-feature">
                <i class="pi pi-align-justify"></i>
                <div class="feature-detail">
                  <strong>软换行</strong>
                  <p>长行自动换行，防止撑开容器</p>
                </div>
              </div>
            </div>

            <h4>支持的格式</h4>
            <ul>
              <li>原始HTTP报文</li>
              <li>cURL命令（自动转换）</li>
              <li>PowerShell脚本（自动转换）</li>
              <li>JavaScript fetch（自动转换）</li>
            </ul>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="2">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-file-export"></i>
            <span>系统日志查看器</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              <strong>v1.8.40新增</strong>: 系统日志查看器功能，方便排查问题和监控系统状态。
            </p>

            <h4>日志类型</h4>
            <div class="log-types">
              <Card class="log-type-card">
                <template #title>
                  <div class="log-title">
                    <i class="pi pi-file" style="color: var(--blue-500)"></i>
                    <span>应用日志</span>
                  </div>
                </template>
                <template #content>
                  <p>应用程序运行日志，包含扫描任务执行记录</p>
                </template>
              </Card>

              <Card class="log-type-card">
                <template #title>
                  <div class="log-title">
                    <i class="pi pi-globe" style="color: var(--green-500)"></i>
                    <span>访问日志</span>
                  </div>
                </template>
                <template #content>
                  <p>HTTP请求访问记录</p>
                </template>
              </Card>

              <Card class="log-type-card">
                <template #title>
                  <div class="log-title">
                    <i class="pi pi-exclamation-triangle" style="color: var(--red-500)"></i>
                    <span>错误日志</span>
                  </div>
                </template>
                <template #content>
                  <p>系统错误和异常记录</p>
                </template>
              </Card>
            </div>

            <h4>功能特性</h4>
            <ul>
              <li><strong>类型切换</strong>: 支持三种日志类型快速切换</li>
              <li><strong>行数设置</strong>: 自定义显示行数（50/100/200/500行）</li>
              <li><strong>实时刷新</strong>: 查看最新日志内容</li>
              <li><strong>暗色主题</strong>: 适配暗色模式</li>
            </ul>

            <h4>使用方式</h4>
            <ol class="steps-list">
              <li>在配置页面找到系统日志查看器入口</li>
              <li>选择要查看的日志类型</li>
              <li>设置显示行数</li>
              <li>点击刷新获取最新日志</li>
            </ol>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="3">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-shopping-cart"></i>
            <span>VulnShop靶场</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <VulnShopHelp />
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="4">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-link"></i>
            <span>Burp Suite插件集成</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              Burp Suite插件支持Legacy API和Montoya API两种版本：
            </p>

            <h4>插件功能</h4>
            <ul>
              <li><strong>右键快速发送</strong>: 在任意HTTP请求上右键发送到SQLMap</li>
              <li><strong>扫描配置选择</strong>: 支持默认配置和常用配置</li>
              <li><strong>请求去重</strong>: 自动检测并跳过重复请求</li>
              <li><strong>二进制检测</strong>: 检测二进制内容并警告</li>
              <li><strong>中文编码</strong>: 正确处理中文字符</li>
              <li><strong>历史配置</strong>: 自动保存到历史配置</li>
            </ul>

            <h4>使用方法</h4>
            <ol class="steps-list">
              <li>
                <strong>配置服务器</strong>
                <p>在插件"服务器配置"标签页设置后端地址（默认: http://127.0.0.1:8775）</p>
              </li>
              <li>
                <strong>测试连接</strong>
                <p>点击"测试连接"验证后端服务状态</p>
              </li>
              <li>
                <strong>发送请求</strong>
                <p>在Burp中右键HTTP请求，选择"Send to SQLMap WebUI"</p>
              </li>
              <li>
                <strong>查看结果</strong>
                <p>在Web界面查看扫描任务状态</p>
              </li>
            </ol>

            <h4>版本要求</h4>
            <div class="version-requirements">
              <div class="version-item">
                <Tag value="Montoya API" severity="info" />
                <span>Java 17+, Burp Suite 2023.1+</span>
              </div>
              <div class="version-item">
                <Tag value="Legacy API" severity="secondary" />
                <span>Java 11+, 兼容旧版本Burp</span>
              </div>
            </div>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="5">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-keyboard"></i>
            <span>键盘快捷键</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <div class="shortcuts-table">
              <table>
                <thead>
                  <tr>
                    <th>快捷键</th>
                    <th>功能</th>
                    <th>适用场景</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><kbd>Alt</kbd> + <kbd>1</kbd></td>
                    <td>跳转到首页</td>
                    <td>全局</td>
                  </tr>
                  <tr>
                    <td><kbd>Alt</kbd> + <kbd>2</kbd></td>
                    <td>跳转到任务列表</td>
                    <td>全局</td>
                  </tr>
                  <tr>
                    <td><kbd>Alt</kbd> + <kbd>3</kbd></td>
                    <td>跳转到添加任务</td>
                    <td>全局</td>
                  </tr>
                  <tr>
                    <td><kbd>Alt</kbd> + <kbd>4</kbd></td>
                    <td>跳转到配置</td>
                    <td>全局</td>
                  </tr>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>F</kbd></td>
                    <td>在编辑器中搜索</td>
                    <td>代码编辑器</td>
                  </tr>
                </tbody>
              </table>
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
import Tag from 'primevue/tag'
import SqlMapParamsHelp from './SqlMapParamsHelp.vue'
import VulnShopHelp from './VulnShopHelp.vue'
</script>

<style scoped lang="scss">
.advanced-features-help {
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

.editor-features {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.75rem;
  margin: 1rem 0;
}

.editor-feature {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;

  i {
    color: var(--primary-color);
    margin-top: 0.2rem;
  }

  .feature-detail {
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
}

.log-types {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.75rem;
  margin: 1rem 0;
}

.log-type-card {
  :deep(.p-card-title) {
    margin-bottom: 0.25rem;
  }

  :deep(.p-card-content) {
    padding-top: 0;

    p {
      margin: 0;
      font-size: 0.9rem;
    }
  }
}

.log-title {
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
  }
}

.version-requirements {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-top: 1rem;
}

.version-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;
}

.shortcuts-table {
  overflow-x: auto;

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

      kbd {
        padding: 0.2rem 0.5rem;
        background: var(--surface-ground);
        border: 1px solid var(--surface-border);
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
  .editor-features,
  .log-types {
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

  .shortcuts-table {
    font-size: 0.8rem;

    th, td {
      padding: 0.5rem;
    }
  }
}
</style>
