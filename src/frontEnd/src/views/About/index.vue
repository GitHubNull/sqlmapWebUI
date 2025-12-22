<template>
  <div class="about-container">
    <Card>
      <template #title>
        <div class="page-title">
          <i class="pi pi-info-circle"></i>
          <span>关于 SQLMap Web UI</span>
        </div>
      </template>
      <template #content>
        <Tabs :value="activeTab" @update:value="handleTabChange" class="about-tabs">
          <TabList>
            <Tab value="0">关于</Tab>
            <Tab value="1">使用帮助</Tab>
            <Tab value="2">开源协议</Tab>
            <Tab value="3">免责声明</Tab>
          </TabList>
          <TabPanels>
            <!-- 关于 -->
            <TabPanel value="0">
            <div class="about-content">
              <div class="app-info">
                <img src="/logo.svg" alt="SQLMap WebUI Logo" class="app-logo-img" />
                <div class="app-details">
                  <h1>SQLMap Web UI</h1>
                  <p class="version">版本 {{ version }}</p>
                  <p class="description">一个现代化的 SQLMap Web 界面，为安全研究人员提供便捷的 SQL 注入测试平台。</p>
                </div>
              </div>
              
              <Divider />
              
              <div class="info-section">
                <h3>功能特性</h3>
                <div class="feature-grid">
                  <div class="feature-item">
                    <i class="pi pi-search"></i>
                    <span>SQL注入自动化检测</span>
                  </div>
                  <div class="feature-item">
                    <i class="pi pi-list"></i>
                    <span>任务管理与监控</span>
                  </div>
                  <div class="feature-item">
                    <i class="pi pi-cog"></i>
                    <span>扫描配置预设管理</span>
                  </div>
                  <div class="feature-item">
                    <i class="pi pi-code"></i>
                    <span>多格式HTTP请求解析</span>
                  </div>
                  <div class="feature-item">
                    <i class="pi pi-server"></i>
                    <span>VulnShop靶场环境</span>
                  </div>
                  <div class="feature-item">
                    <i class="pi pi-link"></i>
                    <span>Burp Suite插件集成</span>
                  </div>
                </div>
              </div>
              
              <Divider />
              
              <div class="info-section">
                <h3>技术栈</h3>
                <div class="tech-tags">
                  <Tag value="Vue 3" severity="success" />
                  <Tag value="TypeScript" severity="info" />
                  <Tag value="PrimeVue" severity="warn" />
                  <Tag value="FastAPI" severity="danger" />
                  <Tag value="Python 3.10+" severity="secondary" />
                  <Tag value="SQLMap" />
                </div>
              </div>
              
              <Divider />
              
              <div class="info-section">
                <h3>链接</h3>
                <div class="link-buttons">
                  <Button 
                    label="GitHub 仓库" 
                    icon="pi pi-github" 
                    severity="secondary"
                    @click="openLink('https://github.com/GitHubNull/sqlmapWebUI')"
                  />
                  <Button 
                    label="报告问题" 
                    icon="pi pi-exclamation-circle" 
                    severity="secondary"
                    @click="openLink('https://github.com/GitHubNull/sqlmapWebUI/issues')"
                  />
                </div>
              </div>
            </div>
            </TabPanel>
            
            <!-- 使用帮助 -->
            <TabPanel value="1">
            <div class="help-content">
              <Accordion :multiple="true" :activeIndex="[0]">
                <AccordionPanel value="0">
                  <AccordionHeader>快速开始</AccordionHeader>
                  <AccordionContent>
                    <div class="help-section">
                      <h4>1. 创建扫描任务</h4>
                      <p>进入"添加任务"页面，粘贴HTTP请求报文（支持cURL、PowerShell、fetch、原始HTTP格式），系统会自动解析并转换。</p>
                      
                      <h4>2. 配置扫描参数</h4>
                      <p>在右侧配置面板中设置检测等级(Level)、风险等级(Risk)、注入技术等参数，或选择预设配置。</p>
                      
                      <h4>3. 提交任务</h4>
                      <p>点击"提交扫描任务"按钮，任务将自动进入队列执行。</p>
                      
                      <h4>4. 查看结果</h4>
                      <p>在任务列表中查看任务状态，点击任务可查看详细的扫描结果和日志。</p>
                    </div>
                  </AccordionContent>
                </AccordionPanel>
                
                <AccordionPanel value="1">
                  <AccordionHeader>扫描配置管理</AccordionHeader>
                  <AccordionContent>
                    <div class="help-section">
                      <h4>默认配置</h4>
                      <p>设置全局默认扫描参数，新建任务时自动应用。</p>
                      
                      <h4>常用配置</h4>
                      <p>保存常用的配置组合，支持增删改查操作。可使用"引导式编辑"可视化配置参数。</p>
                      
                      <h4>历史配置</h4>
                      <p>自动记录历史扫描使用过的配置，方便复用。</p>
                    </div>
                  </AccordionContent>
                </AccordionPanel>
                
                <AccordionPanel value="2">
                  <AccordionHeader>请求头规则</AccordionHeader>
                  <AccordionContent>
                    <div class="help-section">
                      <h4>持久化规则</h4>
                      <p>创建长期有效的请求头规则，支持作用域配置（协议、主机名、端口、路径匹配）。</p>
                      
                      <h4>会话级规则</h4>
                      <p>设置临时请求头，支持TTL自动过期。</p>
                      
                      <h4>优先级</h4>
                      <p>0-100优先级控制，数值越大优先级越高。</p>
                    </div>
                  </AccordionContent>
                </AccordionPanel>
                
                <AccordionPanel value="3">
                  <AccordionHeader>键盘快捷键</AccordionHeader>
                  <AccordionContent>
                    <div class="help-section shortcuts-table">
                      <table>
                        <thead>
                          <tr>
                            <th>快捷键</th>
                            <th>功能</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr><td><kbd>Alt</kbd> + <kbd>1</kbd></td><td>跳转到首页</td></tr>
                          <tr><td><kbd>Alt</kbd> + <kbd>2</kbd></td><td>跳转到任务列表</td></tr>
                          <tr><td><kbd>Alt</kbd> + <kbd>3</kbd></td><td>跳转到添加任务</td></tr>
                          <tr><td><kbd>Alt</kbd> + <kbd>4</kbd></td><td>跳转到配置</td></tr>
                          <tr><td><kbd>Ctrl</kbd> + <kbd>F</kbd></td><td>在编辑器中搜索</td></tr>
                        </tbody>
                      </table>
                    </div>
                  </AccordionContent>
                </AccordionPanel>
              </Accordion>
            </div>
            </TabPanel>
            
            <!-- 开源协议 -->
            <TabPanel value="2">
            <div class="license-content">
              <h2>MIT License</h2>
              <pre class="license-text">{{ licenseText }}</pre>
            </div>
            </TabPanel>
            
            <!-- 免责声明 -->
            <TabPanel value="3">
            <div class="disclaimer-content">
              <Message severity="warn" :closable="false">
                <template #icon>
                  <i class="pi pi-exclamation-triangle" style="font-size: 1.5rem"></i>
                </template>
                本工具仅供合法的安全测试使用，禁止用于非法用途！
              </Message>
              
              <div class="disclaimer-text" v-html="disclaimerHtml"></div>
            </div>
            </TabPanel>
          </TabPanels>
        </Tabs>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import Card from 'primevue/card'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import Divider from 'primevue/divider'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Accordion from 'primevue/accordion'
import AccordionPanel from 'primevue/accordionpanel'
import AccordionHeader from 'primevue/accordionheader'
import AccordionContent from 'primevue/accordioncontent'
import Message from 'primevue/message'

const activeTab = ref<string | number>('0')
const version = '1.7.9'

function handleTabChange(value: string | number) {
  activeTab.value = value
}

const licenseText = `MIT License

Copyright (c) 2024 GitHubNull

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

const disclaimerHtml = `
<h3>重要声明</h3>
<p><strong>SQLMap Web UI</strong> 是一款用于 SQL 注入漏洞检测的安全测试工具。本工具仅供合法的安全测试、渗透测试、安全研究和教育目的使用。</p>

<h3>使用条款</h3>
<p>使用本软件即表示您同意以下条款：</p>

<ol>
  <li><strong>授权使用</strong>: 您必须在获得目标系统所有者明确书面授权后，方可对其进行安全测试。未经授权对他人系统进行测试属于违法行为。</li>
  
  <li><strong>合法用途</strong>: 本工具仅可用于以下合法场景：
    <ul>
      <li>经授权的渗透测试项目</li>
      <li>CTF（Capture The Flag）安全竞赛</li>
      <li>安全研究和漏洞分析</li>
      <li>教育培训目的</li>
      <li>自有系统的安全评估</li>
    </ul>
  </li>
  
  <li><strong>禁止滥用</strong>: 严禁将本工具用于任何非法活动，包括但不限于：
    <ul>
      <li>未经授权访问他人计算机系统</li>
      <li>窃取、破坏或篡改他人数据</li>
      <li>进行网络攻击或恶意行为</li>
      <li>违反当地法律法规的任何行为</li>
    </ul>
  </li>
  
  <li><strong>风险承担</strong>: 使用者应充分了解安全测试可能带来的风险。使用本工具进行测试时，测试目标系统可能会受到影响，使用者需自行承担所有相关风险。</li>
  
  <li><strong>免责条款</strong>:
    <ul>
      <li>本软件按"原样"提供，不提供任何形式的明示或暗示保证</li>
      <li>开发者不对因使用或无法使用本软件而导致的任何直接、间接、偶然、特殊或后果性损害承担责任</li>
      <li>开发者不对用户使用本工具的行为承担任何法律责任</li>
      <li>用户需自行承担使用本软件的全部风险和后果</li>
    </ul>
  </li>
</ol>

<h3>法律合规</h3>
<p>请确保您的使用行为符合：</p>
<ul>
  <li>《中华人民共和国网络安全法》</li>
  <li>《中华人民共和国刑法》相关规定</li>
  <li>所在国家/地区的相关法律法规</li>
  <li>目标系统所在国家/地区的相关法律法规</li>
</ul>
`

function openLink(url: string) {
  window.open(url, '_blank')
}
</script>

<style scoped lang="scss">
.about-container {
  width: 100%;
  max-width: 1000px;
  margin: 0 auto;
}

.page-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 1.25rem;
  
  i {
    color: var(--primary-color);
  }
}

/* 关于页面 */
.about-content {
  padding: 1rem 0;
}

.app-info {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  
  .app-logo-img {
    width: 80px;
    height: 80px;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
  }
  
  .app-details {
    h1 {
      margin: 0 0 0.25rem 0;
      font-size: 1.75rem;
      color: var(--text-color);
    }
    
    .version {
      margin: 0 0 0.5rem 0;
      color: var(--primary-color);
      font-weight: 600;
    }
    
    .description {
      margin: 0;
      color: var(--text-color-secondary);
    }
  }
}

.info-section {
  h3 {
    margin: 0 0 1rem 0;
    color: var(--text-color);
    font-size: 1.1rem;
  }
}

.feature-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0.75rem;
}

.feature-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--surface-ground);
  border-radius: 6px;
  
  i {
    color: var(--primary-color);
  }
}

.tech-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.link-buttons {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}

/* Tabs 样式 */
.about-tabs {
  :deep(.p-tablist) {
    border-bottom: 1px solid var(--surface-border);
    margin-bottom: 1rem;
  }
  
  :deep(.p-tab) {
    padding: 0.75rem 1.25rem;
    margin-right: 0.5rem;
    font-weight: 500;
  }
}

/* 使用帮助 */
.help-content {
  padding: 0.5rem 0;
}

.help-section {
  h4 {
    margin: 0.75rem 0 0.5rem 0;
    color: var(--text-color);
    
    &:first-child {
      margin-top: 0;
    }
  }
  
  p {
    margin: 0 0 0.75rem 0;
    color: var(--text-color-secondary);
    line-height: 1.6;
  }
}

.shortcuts-table {
  table {
    width: 100%;
    border-collapse: collapse;
    
    th, td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid var(--surface-border);
    }
    
    th {
      background: var(--surface-ground);
      font-weight: 600;
    }
    
    kbd {
      padding: 0.2rem 0.5rem;
      background: var(--surface-ground);
      border: 1px solid var(--surface-border);
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.9rem;
    }
  }
}

/* 开源协议 */
.license-content {
  h2 {
    margin: 0 0 1rem 0;
    color: var(--text-color);
  }
  
  .license-text {
    padding: 1rem;
    background: var(--surface-ground);
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.9rem;
    line-height: 1.6;
    white-space: pre-wrap;
    overflow-x: auto;
  }
}

/* 免责声明 */
.disclaimer-content {
  .disclaimer-text {
    margin-top: 1rem;
    line-height: 1.8;
    
    :deep(h3) {
      margin: 1.5rem 0 0.75rem 0;
      color: var(--text-color);
      font-size: 1.1rem;
      
      &:first-child {
        margin-top: 0;
      }
    }
    
    :deep(p) {
      margin: 0 0 0.75rem 0;
      color: var(--text-color-secondary);
    }
    
    :deep(ol), :deep(ul) {
      margin: 0 0 0.75rem 0;
      padding-left: 1.5rem;
      color: var(--text-color-secondary);
      
      li {
        margin-bottom: 0.5rem;
      }
    }
    
    :deep(strong) {
      color: var(--text-color);
    }
  }
}

@media (max-width: 768px) {
  .app-info {
    flex-direction: column;
    text-align: center;
  }
  
  .feature-grid {
    grid-template-columns: 1fr;
  }
  
  .link-buttons {
    justify-content: center;
  }
}
</style>
