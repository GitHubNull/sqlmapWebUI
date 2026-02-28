<template>
  <div class="quick-start-help">
    <Accordion :multiple="true" :activeIndex="[0]">
      <AccordionPanel value="0">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-play-circle"></i>
            <span>快速开始</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <h4>
              <i class="pi pi-plus-circle"></i>
              1. 创建扫描任务
            </h4>
            <p>
              进入<strong>"添加任务"</strong>页面，您可以通过以下方式创建扫描任务：
            </p>
            <ul>
              <li>直接输入目标URL地址</li>
              <li>粘贴HTTP请求报文（支持多种格式自动解析）</li>
              <li>导入cURL命令</li>
            </ul>

            <h4>
              <i class="pi pi-cog"></i>
              2. 配置扫描参数
            </h4>
            <p>
              在右侧配置面板中设置扫描参数：
            </p>
            <ul>
              <li><strong>检测等级(Level)</strong>: 1-5级，越高检测越全面</li>
              <li><strong>风险等级(Risk)</strong>: 1-3级，越高测试越激进</li>
              <li><strong>注入技术</strong>: 选择使用的注入技术(BEUSTQ)</li>
              <li><strong>数据库类型</strong>: 指定目标数据库类型(可选)</li>
            </ul>
            <p>
              或使用<strong>预设配置</strong>快速选择常用配置组合。
            </p>

            <h4>
              <i class="pi pi-send"></i>
              3. 提交任务
            </h4>
            <p>
              点击<strong>"提交扫描任务"</strong>按钮，任务将自动进入队列执行。
              系统会自动解析请求并调用SQLMap引擎进行扫描。
            </p>

            <h4>
              <i class="pi pi-chart-line"></i>
              4. 查看结果
            </h4>
            <p>
              在<strong>任务列表</strong>中查看任务状态，点击任务可查看：
            </p>
            <ul>
              <li>详细的扫描结果和发现的注入点</li>
              <li>实时执行日志</li>
              <li>HTTP请求详情</li>
              <li>Payload信息</li>
            </ul>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="1">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-code"></i>
            <span>HTTP请求格式支持</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              系统支持以下格式的HTTP请求自动解析和转换：
            </p>

            <div class="format-cards">
              <Card class="format-card">
                <template #title>
                  <div class="format-title">
                    <i class="pi pi-terminal"></i>
                    <span>cURL (Bash)</span>
                  </div>
                </template>
                <template #content>
                  <p class="format-desc">Linux/Mac终端cURL命令格式</p>
                  <pre class="code-block"><code>curl -X POST 'http://example.com/api' \
  -H 'Content-Type: application/json' \
  -d '{"id": 1}'</code></pre>
                </template>
              </Card>

              <Card class="format-card">
                <template #title>
                  <div class="format-title">
                    <i class="pi pi-microsoft"></i>
                    <span>cURL (CMD)</span>
                  </div>
                </template>
                <template #content>
                  <p class="format-desc">Windows命令行cURL格式</p>
                  <pre class="code-block"><code>curl -X POST "http://example.com/api" ^
  -H "Content-Type: application/json" ^
  -d "{\"id\": 1}"</code></pre>
                </template>
              </Card>

              <Card class="format-card">
                <template #title>
                  <div class="format-title">
                    <i class="pi pi-power-off"></i>
                    <span>PowerShell</span>
                  </div>
                </template>
                <template #content>
                  <p class="format-desc">PowerShell Invoke-WebRequest</p>
                  <pre class="code-block"><code>Invoke-WebRequest -Uri "http://example.com/api" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"id": 1}'</code></pre>
                </template>
              </Card>

              <Card class="format-card">
                <template #title>
                  <div class="format-title">
                    <i class="pi pi-code"></i>
                    <span>JavaScript fetch</span>
                  </div>
                </template>
                <template #content>
                  <p class="format-desc">浏览器fetch API格式</p>
                  <pre class="code-block"><code>fetch("http://example.com/api", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ id: 1 })
})</code></pre>
                </template>
              </Card>

              <Card class="format-card">
                <template #title>
                  <div class="format-title">
                    <i class="pi pi-globe"></i>
                    <span>原始HTTP报文</span>
                  </div>
                </template>
                <template #content>
                  <p class="format-desc">标准HTTP请求报文格式</p>
                  <pre class="code-block"><code>POST /api HTTP/1.1
Host: example.com
Content-Type: application/json

{"id": 1}</code></pre>
                </template>
              </Card>
            </div>

            <Message severity="info" :closable="false" class="mt-3">
              <template #icon>
                <i class="pi pi-info-circle"></i>
              </template>
              系统会自动检测输入格式并转换为标准HTTP报文，无需手动选择格式。
            </Message>
          </div>
        </AccordionContent>
      </AccordionPanel>

      <AccordionPanel value="2">
        <AccordionHeader>
          <div class="header-with-icon">
            <i class="pi pi-key"></i>
            <span>常用SQLMap参数</span>
          </div>
        </AccordionHeader>
        <AccordionContent>
          <div class="help-section">
            <p>
              本项目完整支持SQLMap的<strong>215个参数</strong>，以下是常用参数说明：
            </p>

            <div class="param-table">
              <table>
                <thead>
                  <tr>
                    <th>参数</th>
                    <th>说明</th>
                    <th>示例值</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><code>--level</code></td>
                    <td>检测等级 (1-5)，越高检测越全面</td>
                    <td>1, 2, 3, 4, 5</td>
                  </tr>
                  <tr>
                    <td><code>--risk</code></td>
                    <td>风险等级 (1-3)，越高测试越激进</td>
                    <td>1, 2, 3</td>
                  </tr>
                  <tr>
                    <td><code>--technique</code></td>
                    <td>注入技术 (B/E/U/S/T/Q)</td>
                    <td>BEUSTQ</td>
                  </tr>
                  <tr>
                    <td><code>--dbms</code></td>
                    <td>指定数据库类型</td>
                    <td>mysql, oracle, mssql</td>
                  </tr>
                  <tr>
                    <td><code>--threads</code></td>
                    <td>并发线程数</td>
                    <td>1-10</td>
                  </tr>
                  <tr>
                    <td><code>--batch</code></td>
                    <td>非交互模式，自动使用默认值</td>
                    <td>-</td>
                  </tr>
                  <tr>
                    <td><code>--random-agent</code></td>
                    <td>使用随机User-Agent</td>
                    <td>-</td>
                  </tr>
                  <tr>
                    <td><code>--answers</code></td>
                    <td>预定义SQLMap询问的答案</td>
                    <td>quit=N,follow=N</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h4>常用参数组合示例</h4>
            <div class="combo-examples">
              <div class="combo-item">
                <Tag value="基础扫描" severity="success" />
                <code>--batch --level=1 --risk=1</code>
              </div>
              <div class="combo-item">
                <Tag value="深度扫描" severity="warn" />
                <code>--batch --level=5 --risk=3 --technique=BEUSTQ</code>
              </div>
              <div class="combo-item">
                <Tag value="MySQL专项" severity="info" />
                <code>--batch --dbms=mysql --level=3</code>
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
</script>

<style scoped lang="scss">
.quick-start-help {
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
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 1rem 0 0.5rem 0;
    color: var(--text-color);
    font-size: 1rem;

    &:first-child {
      margin-top: 0;
    }

    i {
      color: var(--primary-color);
      font-size: 0.9rem;
    }
  }

  p {
    margin: 0 0 0.75rem 0;
    color: var(--text-color-secondary);
    line-height: 1.6;
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

.format-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.format-card {
  :deep(.p-card-title) {
    margin-bottom: 0.5rem;
  }

  :deep(.p-card-content) {
    padding-top: 0;
  }
}

.format-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1rem;

  i {
    color: var(--primary-color);
  }
}

.format-desc {
  font-size: 0.85rem;
  color: var(--text-color-secondary);
  margin-bottom: 0.75rem;
}

.code-block {
  background: var(--surface-ground);
  border-radius: 6px;
  padding: 0.75rem;
  margin: 0;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.8rem;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text-color);
}

.param-table {
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

.combo-examples {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-top: 1rem;
}

.combo-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;

  code {
    font-family: monospace;
    font-size: 0.9rem;
    color: var(--text-color);
  }
}

.mt-3 {
  margin-top: 1rem;
}

@media (max-width: 768px) {
  .format-cards {
    grid-template-columns: 1fr;
  }

  .param-table {
    font-size: 0.8rem;

    th, td {
      padding: 0.5rem;
    }
  }
}
</style>
