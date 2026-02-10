<template>
  <div class="add-task-container">
    <div class="page-header">
      <h2>添加扫描任务</h2>
      <p class="subtitle">从浏览器DevTools复制HTTP请求报文，转换后提交扫描</p>
    </div>

    <div class="content-wrapper">
      <!-- 左侧：报文输入和编辑 -->
      <div class="left-panel">
        <!-- 格式输入区域 -->
        <Card class="input-card">
          <template #title>
            <div class="card-title-row">
              <span>报文输入</span>
              <div class="format-indicator" v-if="detectedFormat !== 'unknown'">
                <Tag :severity="formatSeverity">{{ formatDisplayName }}</Tag>
              </div>
            </div>
          </template>
          <template #content>
            <HttpCodeEditor
              v-model="inputContent"
              :placeholder="inputPlaceholder"
              min-height="100px"
              max-height="none"
              class="flex-editor"
              @change="onInputChange"
            />
            <div class="input-actions">
              <Button 
                label="解析转换" 
                icon="pi pi-sync" 
                @click="parseInput"
                :disabled="!inputContent.trim()"
              />
              <Button 
                label="清空" 
                icon="pi pi-trash" 
                severity="secondary"
                @click="clearInput"
              />
            </div>
          </template>
        </Card>

        <!-- HTTP报文编辑器 -->
        <Card class="editor-card">
          <template #title>
            <div class="card-title-row">
              <span>HTTP报文编辑</span>
              <Tag severity="info" v-tooltip="'在参数值中添加 * 标记注入点'">
                <i class="pi pi-info-circle"></i> 使用 * 标记注入点
              </Tag>
            </div>
          </template>
          <template #content>
            <HttpCodeEditor
              v-model="rawHttpContent"
              :placeholder="httpPlaceholder"
              min-height="100px"
              max-height="none"
              class="flex-editor"
            />
            <div class="editor-status" v-if="parsedRequest">
              <span class="status-item">
                <i class="pi pi-globe"></i>
                {{ parsedRequest.method }} {{ parsedRequest.host }}
              </span>
              <span class="status-item">
                <i class="pi pi-link"></i>
                {{ parsedRequest.path }}
              </span>
            </div>
          </template>
        </Card>
      </div>

      <!-- 右侧：扫描配置 -->
      <div class="right-panel">
        <!-- 配置预设选择 -->
        <Card class="config-card">
          <template #title>
            <div class="card-title-row">
              <span>扫描配置</span>
              <Button 
                icon="pi pi-refresh" 
                severity="secondary" 
                text 
                rounded 
                size="small"
                @click="resetConfig"
                v-tooltip="'重置配置'"
              />
            </div>
          </template>
          <template #content>
            <!-- 上中下布局容器 -->
            <div class="config-layout">
              <!-- 上部：切换区域 + 配置显示区域 -->
              <div class="config-top-section">
                <!-- 上上：模式切换按钮 -->
                <div class="config-mode-switch-bar">
                  <div class="mode-switch-tabs">
                    <button
                      class="mode-tab"
                      :class="{ active: configMode === 'preset' }"
                      @click="configMode = 'preset'"
                    >
                      <i class="pi pi-bookmark"></i>
                      <span>使用预设</span>
                    </button>
                    <button
                      class="mode-tab"
                      :class="{ active: configMode === 'custom' }"
                      @click="configMode = 'custom'"
                    >
                      <i class="pi pi-sliders-h"></i>
                      <span>自定义配置</span>
                    </button>
                  </div>
                  <div class="mode-switch-hint">
                    <i class="pi pi-info-circle"></i>
                    <span>{{ configMode === 'preset' ? '选择一个预设配置' : '手动配置扫描参数' }}</span>
                  </div>
                </div>

                <!-- 上下：配置显示区域（独立滚动） -->
                <div class="config-content-area">
            <div v-if="configMode === 'preset'" class="preset-mode-content">
              <!-- 预设类型选择器 -->
              <div class="preset-category-selector">
                <label class="selector-label">选择预设类型</label>
                <Select
                  v-model="presetCategory"
                  :options="PRESET_CATEGORY_OPTIONS"
                  optionLabel="label"
                  optionValue="value"
                  class="w-full preset-category-select"
                >
                  <template #value="slotProps">
                    <div v-if="slotProps.value" class="preset-category-item">
                      <i :class="PRESET_CATEGORY_OPTIONS.find(o => o.value === slotProps.value)?.icon"></i>
                      <span>{{ PRESET_CATEGORY_OPTIONS.find(o => o.value === slotProps.value)?.label }}</span>
                    </div>
                    <span v-else>选择预设类型</span>
                  </template>
                  <template #option="slotProps">
                    <div class="preset-category-item">
                      <i :class="slotProps.option.icon" :style="{ color: slotProps.option.color }"></i>
                      <span>{{ slotProps.option.label }}</span>
                    </div>
                  </template>
                </Select>
              </div>

              <!-- 预设列表显示区域 -->
              <div class="preset-list-area">
                <!-- 默认配置 -->
                <div v-if="presetCategory === 'default'" class="preset-list-container preset-default">
                  <div class="preset-list-header">
                    <i class="pi pi-star"></i>
                    <span>默认配置</span>
                    <span class="preset-count">{{ presetStore.defaultPreset ? 1 : 0 }} 项</span>
                  </div>
                  <div class="preset-list-content">
                    <div 
                      v-if="presetStore.defaultPreset"
                      class="preset-card preset-card-default"
                      :class="{ selected: selectedPresetId === presetStore.defaultPreset.id }"
                      @click="selectPreset(presetStore.defaultPreset)"
                    >
                      <div class="preset-card-header">
                        <span class="preset-name">{{ presetStore.defaultPreset.name }}</span>
                        <Tag severity="success" value="默认" />
                      </div>
                      <div class="preset-card-desc">{{ presetStore.defaultPreset.description || '系统默认扫描配置' }}</div>
                      <div class="preset-card-params">
                        <code v-if="presetStore.defaultPreset.parameter_string">{{ presetStore.defaultPreset.parameter_string.substring(0, 80) }}{{ presetStore.defaultPreset.parameter_string.length > 80 ? '...' : '' }}</code>
                        <span v-else class="default-params-hint">--batch (使用默认参数)</span>
                      </div>
                    </div>
                    <div v-else class="preset-empty-hint">
                      <i class="pi pi-info-circle"></i>
                      <span>暂无默认配置</span>
                    </div>
                  </div>
                </div>

                <!-- 常用配置 -->
                <div v-else-if="presetCategory === 'common'" class="preset-list-container preset-common">
                  <div class="preset-list-header">
                    <i class="pi pi-bookmark"></i>
                    <span>常用配置</span>
                    <span class="preset-count">{{ presetStore.presetConfigs.length }} 项</span>
                  </div>
                  <div class="preset-list-content">
                    <div 
                      v-for="preset in presetStore.presetConfigs" 
                      :key="preset.id"
                      class="preset-card preset-card-common"
                      :class="{ selected: selectedPresetId === preset.id }"
                      @click="selectPreset(preset)"
                    >
                      <div class="preset-card-header">
                        <span class="preset-name">{{ preset.name }}</span>
                      </div>
                      <div class="preset-card-desc">{{ preset.description || '暂无描述' }}</div>
                      <div class="preset-card-params">
                        <code v-if="preset.parameter_string">{{ preset.parameter_string.substring(0, 80) }}{{ preset.parameter_string.length > 80 ? '...' : '' }}</code>
                        <span v-else class="default-params-hint">--batch (使用默认参数)</span>
                      </div>
                    </div>
                    <div v-if="presetStore.presetConfigs.length === 0" class="preset-empty-hint">
                      <i class="pi pi-inbox"></i>
                      <span>暂无常用配置，您可以在自定义配置后保存为预设</span>
                    </div>
                  </div>
                </div>

                <!-- 历史配置 -->
                <div v-else-if="presetCategory === 'history'" class="preset-list-container preset-history">
                  <div class="preset-list-header">
                    <i class="pi pi-history"></i>
                    <span>历史配置</span>
                    <span class="preset-count">{{ presetStore.historyConfigs.length }} 项</span>
                  </div>
                  <div class="preset-list-content">
                    <div 
                      v-for="preset in presetStore.historyConfigs.slice(0, 10)" 
                      :key="preset.id"
                      class="preset-card preset-card-history"
                      :class="{ selected: selectedPresetId === preset.id }"
                      @click="selectPreset(preset)"
                    >
                      <div class="preset-card-header">
                        <span class="preset-name">{{ preset.name }}</span>
                        <Tag severity="warn" value="历史" />
                      </div>
                      <div class="preset-card-params">
                        <code v-if="preset.parameter_string">{{ preset.parameter_string.substring(0, 80) }}{{ preset.parameter_string.length > 80 ? '...' : '' }}</code>
                        <span v-else class="default-params-hint">--batch (使用默认参数)</span>
                      </div>
                    </div>
                    <div v-if="presetStore.historyConfigs.length === 0" class="preset-empty-hint">
                      <i class="pi pi-clock"></i>
                      <span>暂无历史配置记录</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- 自定义配置模式界面 -->
            <div v-else class="custom-mode-content">
            <Fieldset legend="检测选项" :toggleable="true" :collapsed="false" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item">
                  <label>检测等级 (Level)</label>
                  <Select
                    v-model="currentOptions.level"
                    :options="LEVEL_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>风险等级 (Risk)</label>
                  <Select
                    v-model="currentOptions.risk"
                    :options="RISK_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-grid">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.smart" inputId="smart" binary />
                  <label for="smart">智能检测 (--smart)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.textOnly" inputId="textOnly" binary />
                  <label for="textOnly">仅文本比较 (--text-only)</label>
                </div>
              </div>
            </Fieldset>

            <!-- Injection 注入选项 -->
            <Fieldset legend="注入选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item">
                  <label>目标数据库 (DBMS)</label>
                  <Select
                    v-model="currentOptions.dbms"
                    :options="DBMS_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    placeholder="自动检测"
                    showClear
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>操作系统 (OS)</label>
                  <Select
                    v-model="currentOptions.os"
                    :options="OS_OPTIONS"
                    optionLabel="label"
                    optionValue="value"
                    placeholder="自动检测"
                    showClear
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-item full-width">
                <label>测试参数 (-p)</label>
                <InputText 
                  v-model="currentOptions.testParameter" 
                  placeholder="指定测试参数，如: id,name" 
                  class="w-full"
                />
              </div>
              <div class="config-item full-width">
                <label>跳过参数 (--skip)</label>
                <InputText 
                  v-model="currentOptions.skip" 
                  placeholder="跳过测试的参数，如: token,csrf" 
                  class="w-full"
                />
              </div>
              <div class="config-grid">
                <div class="config-item">
                  <label>注入前缀 (--prefix)</label>
                  <InputText 
                    v-model="currentOptions.prefix" 
                    placeholder="如: '" 
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>注入后缀 (--suffix)</label>
                  <InputText 
                    v-model="currentOptions.suffix" 
                    placeholder="如: -- -" 
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-item full-width">
                <label>Tamper脚本 (--tamper)</label>
                <InputText 
                  v-model="currentOptions.tamper" 
                  placeholder="如: space2comment,randomcase" 
                  class="w-full"
                />
              </div>
            </Fieldset>

            <!-- Techniques 技术选项 -->
            <Fieldset legend="技术选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-item full-width">
                <label>注入技术 (--technique)</label>
                <div class="technique-checkboxes">
                  <div v-for="tech in TECHNIQUE_ITEMS" :key="tech.value" class="technique-item">
                    <Checkbox 
                      v-model="selectedTechniques" 
                      :inputId="'tech-' + tech.value" 
                      :value="tech.value" 
                    />
                    <label :for="'tech-' + tech.value">{{ tech.label }}</label>
                  </div>
                </div>
              </div>
              <div class="config-item">
                <label>时间盲注延迟 (--time-sec)</label>
                <InputNumber
                  v-model="currentOptions.timeSec"
                  :min="1"
                  :max="60"
                  suffix=" 秒"
                  showButtons
                  class="w-full"
                />
              </div>
            </Fieldset>

            <!-- Request 请求选项 -->
            <Fieldset legend="请求选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item">
                  <label>线程数 (--threads)</label>
                  <InputNumber
                    v-model="currentOptions.threads"
                    :min="1"
                    :max="10"
                    showButtons
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>超时时间 (--timeout)</label>
                  <InputNumber
                    v-model="currentOptions.timeout"
                    :min="1"
                    :max="300"
                    suffix=" 秒"
                    showButtons
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-grid">
                <div class="config-item">
                  <label>重试次数 (--retries)</label>
                  <InputNumber
                    v-model="currentOptions.retries"
                    :min="0"
                    :max="10"
                    showButtons
                    class="w-full"
                  />
                </div>
                <div class="config-item">
                  <label>请求延迟 (--delay)</label>
                  <InputNumber
                    v-model="currentOptions.delay"
                    :min="0"
                    :max="60"
                    suffix=" 秒"
                    showButtons
                    class="w-full"
                  />
                </div>
              </div>
              <div class="config-grid">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.randomAgent" inputId="randomAgent" binary />
                  <label for="randomAgent">随机User-Agent</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.tor" inputId="tor" binary />
                  <label for="tor">使用Tor代理</label>
                </div>
              </div>
              <div class="config-item full-width">
                <label>代理 (--proxy)</label>
                <InputText 
                  v-model="currentOptions.proxy" 
                  placeholder="如: http://127.0.0.1:8080" 
                  class="w-full"
                />
              </div>
            </Fieldset>

            <!-- Enumeration 枚举选项 -->
            <Fieldset legend="枚举选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="enum-checkboxes">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getBanner" inputId="getBanner" binary />
                  <label for="getBanner">获取Banner (--banner)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getCurrentUser" inputId="getCurrentUser" binary />
                  <label for="getCurrentUser">当前用户 (--current-user)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getCurrentDb" inputId="getCurrentDb" binary />
                  <label for="getCurrentDb">当前数据库 (--current-db)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.isDba" inputId="isDba" binary />
                  <label for="isDba">是否DBA (--is-dba)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getDbs" inputId="getDbs" binary />
                  <label for="getDbs">获取所有数据库 (--dbs)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getTables" inputId="getTables" binary />
                  <label for="getTables">获取所有表 (--tables)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getColumns" inputId="getColumns" binary />
                  <label for="getColumns">获取所有列 (--columns)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.dumpTable" inputId="dumpTable" binary />
                  <label for="dumpTable">导出表数据 (--dump)</label>
                </div>
              </div>
            </Fieldset>

            <!-- General 通用选项 -->
            <Fieldset legend="通用选项" :toggleable="true" :collapsed="true" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.batch" inputId="batch" binary />
                  <label for="batch">批处理模式 (--batch)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.forms" inputId="forms" binary />
                  <label for="forms">解析表单 (--forms)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.flushSession" inputId="flushSession" binary />
                  <label for="flushSession">刷新会话 (--flush-session)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.freshQueries" inputId="freshQueries" binary />
                  <label for="freshQueries">刷新查询 (--fresh-queries)</label>
                </div>
              </div>
              <div class="config-item">
                <label>详细级别 (--verbose)</label>
                <Select
                  v-model="currentOptions.verbose"
                  :options="VERBOSE_OPTIONS"
                  optionLabel="label"
                  optionValue="value"
                  class="w-full"
                />
              </div>
            </Fieldset>
            </div>
                </div>
              </div>

              <!-- 中部：当前扫描参数预览（带语法高亮） -->
              <div class="config-middle-section">
                <div class="param-preview-header">
                  <div class="param-preview-title">
                    <i class="pi pi-terminal"></i>
                    <span>当前扫描参数</span>
                  </div>
                  <Button 
                    icon="pi pi-copy" 
                    text 
                    rounded 
                    size="small"
                    @click="copyCommandLine"
                    v-tooltip="'复制命令'"
                  />
                </div>
                <div class="cmdline-preview-box">
                  <span class="cmdline-prefix">sqlmap</span>
                  <template v-if="cmdlineArgs.length > 0">
                    <span 
                      v-for="(arg, index) in cmdlineArgs" 
                      :key="index" 
                      class="cmdline-arg"
                      :class="getArgClass(arg)"
                      v-html="formatArg(arg)"
                    ></span>
                  </template>
                  <span v-else class="cmdline-default">(默认参数)</span>
                </div>
              </div>

              <!-- 下部：操作按钮 -->
              <div class="config-bottom-section">
                <Button 
                  label="保存为预设" 
                  icon="pi pi-save" 
                  severity="secondary"
                  @click="showSavePresetDialog = true"
                  class="save-preset-btn"
                  :disabled="!canSavePreset"
                  v-tooltip.top="!canSavePreset ? '只有自定义配置模式才能保存为预设' : ''"
                />
                <Button 
                  label="提交扫描任务" 
                  icon="pi pi-send" 
                  class="submit-btn"
                  :loading="submitting"
                  :disabled="!canSubmit"
                  @click="submitTask"
                  v-tooltip.top="!canSubmit ? submitDisabledReason : ''"
                />
              </div>
              <small class="submit-hint" v-if="!canSubmit">
                {{ submitDisabledReason }}
              </small>
            </div>
          </template>
        </Card>
      </div>
    </div>

    <!-- 保存预设对话框 -->
    <Dialog 
      v-model:visible="showSavePresetDialog" 
      header="保存为预设" 
      :modal="true"
      :style="{ width: '400px' }"
    >
      <div class="dialog-content">
        <div class="field">
          <label for="presetName">预设名称 *</label>
          <InputText id="presetName" v-model="newPresetName" class="w-full" />
        </div>
        <div class="field">
          <label for="presetDesc">描述（可选）</label>
          <Textarea id="presetDesc" v-model="newPresetDescription" rows="3" class="w-full" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" @click="showSavePresetDialog = false" />
        <Button label="保存" @click="saveAsPreset" :disabled="!newPresetName.trim()" />
      </template>
    </Dialog>

    <!-- 消息提示 -->
    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import Card from 'primevue/card'
import Button from 'primevue/button'
import Select from 'primevue/select'
import HttpCodeEditor from '@/components/HttpCodeEditor.vue'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Checkbox from 'primevue/checkbox'
import Fieldset from 'primevue/fieldset'
import Tag from 'primevue/tag'
import Dialog from 'primevue/dialog'
import Toast from 'primevue/toast'

import { useScanPresetStore } from '@/stores/scanPreset'
import { 
  parseHttpRequest, 
  detectFormat, 
  getFormatDisplayName,
  extractRequestFromRawHttp,
  type ParsedHttpRequest,
  type RequestFormat
} from '@/utils/httpRequestParser'
import { 
  LEVEL_OPTIONS, 
  RISK_OPTIONS, 
  DBMS_OPTIONS,
  DEFAULT_SCAN_OPTIONS,
  type ScanOptions
} from '@/types/scanPreset'
import { request } from '@/api/request'

const router = useRouter()
const toast = useToast()
const presetStore = useScanPresetStore()

// OS选项
const OS_OPTIONS = [
  { label: '自动检测', value: '' },
  { label: 'Linux', value: 'Linux' },
  { label: 'Windows', value: 'Windows' }
]

// 注入技术单独选项
const TECHNIQUE_ITEMS = [
  { label: 'B (布尔盲注)', value: 'B' },
  { label: 'E (报错注入)', value: 'E' },
  { label: 'U (联合查询)', value: 'U' },
  { label: 'S (堆叠查询)', value: 'S' },
  { label: 'T (时间盲注)', value: 'T' },
  { label: 'Q (内联查询)', value: 'Q' }
]

// Verbose选项
const VERBOSE_OPTIONS = [
  { label: '0 (静默)', value: 0 },
  { label: '1 (默认)', value: 1 },
  { label: '2 (调试)', value: 2 },
  { label: '3 (更多调试)', value: 3 },
  { label: '4 (HTTP请求)', value: 4 },
  { label: '5 (HTTP响应头)', value: 5 },
  { label: '6 (HTTP响应体)', value: 6 }
]

// 输入状态
const inputContent = ref('')
const rawHttpContent = ref('')
const parsedRequest = ref<ParsedHttpRequest | null>(null)
const detectedFormat = ref<RequestFormat>('unknown')

// 配置状态
const configMode = ref<'preset' | 'custom'>('preset')  // 配置模式：预设/自定义
const presetCategory = ref<'default' | 'common' | 'history'>('default')  // 预设类型
const selectedPresetId = ref<number | null>(null)
const currentOptions = ref<ScanOptions>({ ...DEFAULT_SCAN_OPTIONS })
const selectedTechniques = ref<string[]>(['B', 'E', 'U', 'S', 'T', 'Q'])

// 预设类型选项
const PRESET_CATEGORY_OPTIONS = [
  { label: '默认配置', value: 'default', icon: 'pi pi-star', color: '#10b981' },
  { label: '常用配置', value: 'common', icon: 'pi pi-bookmark', color: '#6366f1' },
  { label: '历史配置', value: 'history', icon: 'pi pi-history', color: '#f59e0b' }
]

// 提交状态
const submitting = ref(false)

// 对话框状态
const showSavePresetDialog = ref(false)
const newPresetName = ref('')
const newPresetDescription = ref('')

// 计算属性
const formatDisplayName = computed(() => getFormatDisplayName(detectedFormat.value))

const formatSeverity = computed(() => {
  switch (detectedFormat.value) {
    case 'curl_bash':
    case 'curl_cmd':
    case 'raw_http':
      return 'success'
    case 'powershell':
      return 'info'
    case 'fetch_js':
    case 'fetch_nodejs':
      return 'warn'
    default:
      return 'secondary'
  }
})

const canSubmit = computed(() => {
  // 必须有有效的HTTP报文
  if (!rawHttpContent.value.trim() || !parsedRequest.value) {
    return false
  }
  // 如果是预设模式，必须选择了预设
  if (configMode.value === 'preset' && !selectedPresetId.value) {
    return false
  }
  return true
})

// 是否可以保存为预设（只有自定义配置模式才能保存）
const canSavePreset = computed(() => {
  return configMode.value === 'custom'
})

// 提交按钮禁用提示文字
const submitDisabledReason = computed(() => {
  if (!rawHttpContent.value.trim() || !parsedRequest.value) {
    return '请先输入并解析HTTP报文'
  }
  if (configMode.value === 'preset' && !selectedPresetId.value) {
    return '请先选择一个预设配置'
  }
  return ''
})

// 命令行参数数组
const cmdlineArgs = computed(() => {
  const args: string[] = []
  const opts = currentOptions.value
  const defaults = DEFAULT_SCAN_OPTIONS
  
  // 按优先级添加参数
  if (opts.level !== defaults.level) args.push(`--level=${opts.level}`)
  if (opts.risk !== defaults.risk) args.push(`--risk=${opts.risk}`)
  if (opts.technique && opts.technique !== 'BEUSTQ') args.push(`--technique=${opts.technique}`)
  if (opts.dbms) args.push(`--dbms=${opts.dbms}`)
  if (opts.testParameter) args.push(`-p=${opts.testParameter}`)
  if (opts.threads && opts.threads !== defaults.threads) args.push(`--threads=${opts.threads}`)
  if (opts.timeout && opts.timeout !== defaults.timeout) args.push(`--timeout=${opts.timeout}`)
  if (opts.proxy) args.push(`--proxy=${opts.proxy}`)
  if (opts.tamper) args.push(`--tamper=${opts.tamper}`)
  if (opts.smart) args.push('--smart')
  if (opts.textOnly) args.push('--text-only')
  if (opts.randomAgent) args.push('--random-agent')
  if (opts.tor) args.push('--tor')
  if (opts.batch) args.push('--batch')
  if (opts.forms) args.push('--forms')
  if (opts.flushSession) args.push('--flush-session')
  if (opts.freshQueries) args.push('--fresh-queries')
  if (opts.getBanner) args.push('--banner')
  if (opts.getCurrentUser) args.push('--current-user')
  if (opts.getCurrentDb) args.push('--current-db')
  if (opts.isDba) args.push('--is-dba')
  if (opts.getDbs) args.push('--dbs')
  if (opts.getTables) args.push('--tables')
  if (opts.getColumns) args.push('--columns')
  if (opts.dumpTable) args.push('--dump')
  if (opts.prefix) args.push(`--prefix="${opts.prefix}"`)
  if (opts.suffix) args.push(`--suffix="${opts.suffix}"`)
  if (opts.skip) args.push(`--skip=${opts.skip}`)
  if (opts.timeSec && opts.timeSec !== 5) args.push(`--time-sec=${opts.timeSec}`)
  if (opts.retries && opts.retries !== 3) args.push(`--retries=${opts.retries}`)
  if (opts.delay && opts.delay !== 0) args.push(`--delay=${opts.delay}`)
  if (opts.verbose !== undefined && opts.verbose !== 1) args.push(`-v=${opts.verbose}`)
  
  return args
})

// 获取参数的CSS类（用于语法高亮）
function getArgClass(arg: string): string {
  // 短参数 (-r, -u, -v 等)
  if (/^-[a-zA-Z]=?/.test(arg)) return 'arg-short'
  // 检测/注入相关
  if (/^--(level|risk|technique|dbms|os|prefix|suffix|tamper)/.test(arg)) return 'arg-detection'
  // 性能相关
  if (/^--(threads|timeout|retries|delay|time-sec)/.test(arg)) return 'arg-performance'
  // 枚举相关
  if (/^--(banner|current-user|current-db|is-dba|dbs|tables|columns|dump)/.test(arg)) return 'arg-enumerate'
  // 代理/网络相关
  if (/^--(proxy|tor|cookie|user-agent|random-agent)/.test(arg)) return 'arg-network'
  // 开关类参数
  if (/^--(batch|smart|text-only|forms|flush-session|fresh-queries)/.test(arg)) return 'arg-switch'
  return 'arg-long'
}

// 格式化参数（添加语法高亮）
function formatArg(arg: string): string {
  const eqIndex = arg.indexOf('=')
  if (eqIndex > 0) {
    const name = arg.substring(0, eqIndex)
    const value = arg.substring(eqIndex + 1)
    return `<span class="arg-name">${name}</span><span class="arg-equals">=</span><span class="arg-value">${value}</span>`
  }
  return `<span class="arg-name">${arg}</span>`
}

// 复制命令行
function copyCommandLine() {
  const fullCmd = 'sqlmap ' + cmdlineArgs.value.join(' ')
  navigator.clipboard.writeText(fullCmd).then(() => {
    toast.add({
      severity: 'success',
      summary: '已复制',
      detail: `命令行参数已复制到剪贴板`,
      life: 2000
    })
  }).catch(err => {
    console.error('复制失败:', err)
    toast.add({
      severity: 'error',
      summary: '复制失败',
      detail: '无法访问剪贴板',
      life: 3000
    })
  })
}

// 监听技术选择变化
watch(selectedTechniques, (newVal) => {
  currentOptions.value.technique = newVal.join('')
}, { deep: true })

const inputPlaceholder = `粘贴从Chrome DevTools复制的HTTP请求报文

支持的格式：
• cURL (bash/cmd)
• PowerShell (Invoke-WebRequest)
• fetch (JavaScript/Node.js)
• 原始HTTP报文

示例 (cURL):
curl 'https://example.com/api/user?id=1' \\
  -H 'Content-Type: application/json'`

const httpPlaceholder = `转换后的HTTP报文将显示在这里...

您可以直接编辑报文内容
使用 * 标记注入点，例如：
GET /api/user?id=1* HTTP/1.1`

// 方法
function onInputChange() {
  detectedFormat.value = detectFormat(inputContent.value)
}

function parseInput() {
  const result = parseHttpRequest(inputContent.value)
  
  if (result.success && result.data && result.rawHttp) {
    parsedRequest.value = result.data
    rawHttpContent.value = result.rawHttp
    detectedFormat.value = result.format || 'unknown'
    
    toast.add({
      severity: 'success',
      summary: '解析成功',
      detail: `已将 ${formatDisplayName.value} 格式转换为HTTP报文`,
      life: 3000
    })
  } else {
    toast.add({
      severity: 'error',
      summary: '解析失败',
      detail: result.error || '无法解析输入内容',
      life: 5000
    })
  }
}

function clearInput() {
  inputContent.value = ''
  rawHttpContent.value = ''
  parsedRequest.value = null
  detectedFormat.value = 'unknown'
}

// 选择预设配置
async function selectPreset(preset: any) {
  if (!preset || !preset.id) return
  
  try {
    selectedPresetId.value = preset.id
    
    // 直接从预设对象中获取配置，确保参数预览即时更新
    if (preset.options && typeof preset.options === 'object') {
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...preset.options }
    } else {
      // 如果预设对象没有options，通过API加载
      await presetStore.selectPreset(preset.id)
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...presetStore.currentOptions }
    }
    
    // 更新technique选择
    if (currentOptions.value.technique) {
      selectedTechniques.value = currentOptions.value.technique.split('')
    } else {
      selectedTechniques.value = ['B', 'E', 'U', 'S', 'T', 'Q']
    }
    
    toast.add({
      severity: 'success',
      summary: '已选择预设',
      detail: `已应用 "${preset.name}" 配置`,
      life: 2000
    })
  } catch (error) {
    console.error('Failed to apply preset:', error)
    toast.add({
      severity: 'error',
      summary: '应用失败',
      detail: '无法应用预设配置',
      life: 3000
    })
  }
}

function resetConfig() {
  currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
  selectedPresetId.value = null
  selectedTechniques.value = ['B', 'E', 'U', 'S', 'T', 'Q']
}

async function saveAsPreset() {
  if (!newPresetName.value.trim()) return
  
  const result = await presetStore.saveCurrentAsPreset(
    newPresetName.value.trim(),
    newPresetDescription.value.trim() || undefined
  )
  
  if (result) {
    toast.add({
      severity: 'success',
      summary: '保存成功',
      detail: `预设 "${newPresetName.value}" 已保存`,
      life: 3000
    })
    showSavePresetDialog.value = false
    newPresetName.value = ''
    newPresetDescription.value = ''
  } else {
    toast.add({
      severity: 'error',
      summary: '保存失败',
      detail: '无法保存预设配置',
      life: 5000
    })
  }
}

function getEffectiveOptions(): Record<string, any> {
  const result: Record<string, any> = {}
  const defaults = DEFAULT_SCAN_OPTIONS
  
  for (const [key, value] of Object.entries(currentOptions.value)) {
    const defaultValue = (defaults as any)[key]
    if (value !== defaultValue && value !== null && value !== undefined && value !== '') {
      result[key] = value
    }
  }
  
  // 确保batch选项始终存在
  result.batch = true
  
  return result
}

async function submitTask() {
  if (!canSubmit.value) return
  
  const requestInfo = extractRequestFromRawHttp(rawHttpContent.value)
  if (!requestInfo) {
    toast.add({
      severity: 'error',
      summary: '提交失败',
      detail: '无法解析HTTP报文，请检查格式',
      life: 5000
    })
    return
  }
  
  submitting.value = true
  
  try {
    const taskData = {
      scanUrl: requestInfo.url,
      host: requestInfo.host,
      method: requestInfo.method,
      headers: requestInfo.headers,
      body: requestInfo.body,
      options: getEffectiveOptions()
    }
    
    // 调用Web端专用的任务添加API
    await request.post('/web/admin/task/add', taskData)
    
    // 保存到历史记录
    const urlPath = requestInfo.url.split('?')[0] || ''
    const hostPart = requestInfo.host && urlPath ? urlPath.split(requestInfo.host)[1] : ''
    const historyName = `${requestInfo.method} ${requestInfo.host}${hostPart || '/'}`
    await presetStore.addToHistory(historyName.substring(0, 50))
    
    toast.add({
      severity: 'success',
      summary: '提交成功',
      detail: '扫描任务已创建',
      life: 3000
    })
    
    router.push('/tasks')
    
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '提交失败',
      detail: error.message || '创建扫描任务失败',
      life: 5000
    })
  } finally {
    submitting.value = false
  }
}

// 生命周期
onMounted(async () => {
  try {
    await presetStore.loadConfigOptions()
    if (presetStore.defaultPreset) {
      selectedPresetId.value = presetStore.defaultPreset.id || null
    }
  } catch (error) {
    console.error('Failed to load config options:', error)
    // 使用默认配置
    currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
  }
})
</script>

<style scoped>
.add-task-container {
  width: 100%;
  height: 100%;
  padding: 0.75rem 1rem;
  margin: 0;
  box-sizing: border-box;
}

.page-header {
  margin-bottom: 0.75rem;
}

.page-header h2 {
  margin: 0 0 0.25rem 0;
  color: var(--text-color);
  font-size: 1.25rem;
}

.page-header .subtitle {
  margin: 0;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}

.content-wrapper {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 1rem;
  height: calc(100vh - 180px);
  max-height: 800px;
  min-width: 1000px;
}

.left-panel {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  min-height: 0;
  overflow: visible;
}

.right-panel {
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  min-width: 400px;
}

/* 两个编辑器卡片高度相等 */
.input-card,
.editor-card {
  flex: 1 1 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  overflow: visible;
}

.input-card :deep(.p-card-body),
.editor-card :deep(.p-card-body) {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: visible;
}

.input-card :deep(.p-card-content),
.editor-card :deep(.p-card-content) {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

/* 修复Card标题被遮挡问题 */
.input-card :deep(.p-card-title),
.editor-card :deep(.p-card-title) {
  position: relative;
  z-index: 1;
  background: var(--surface-card);
  padding-right: 1rem;
}

.card-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

/* HttpCodeEditor 组件样式 */
.input-card :deep(.http-code-editor),
.editor-card :deep(.http-code-editor) {
  flex: 1;
  min-height: 120px;
  max-height: none;
}

.flex-editor {
  flex: 1;
  min-height: 0;
}

/* 按钮区域确保可见 */
.input-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
  padding: 0.25rem 0;
  flex-shrink: 0;
  position: relative;
  z-index: 10;
  background: var(--surface-card);
}

.editor-status {
  display: flex;
  gap: 1rem;
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--surface-border);
}

.status-item {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}

/* 配置卡片 */
.config-card {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.config-card :deep(.p-card-header) {
  padding: 0.75rem 1rem;
  flex-shrink: 0;
}

.config-card :deep(.p-card-title) {
  padding: 0;
  margin: 0;
}

.config-card :deep(.p-card-body) {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 0.75rem 1rem;
}

.config-card :deep(.p-card-content) {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 0;
}

/* 上中下布局容器 */
.config-layout {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  gap: 0;
}

/* 上部：切换区域 + 配置显示区域 */
.config-top-section {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}

/* 配置显示区域（独立滚动） */
.config-content-area {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  min-height: 0;
  padding: 0.5rem 0;
}

.config-content-area::-webkit-scrollbar {
  width: 8px;
}

.config-content-area::-webkit-scrollbar-track {
  background: rgba(0, 0, 0, 0.05);
  border-radius: 4px;
}

.config-content-area::-webkit-scrollbar-thumb {
  background: rgba(99, 102, 241, 0.3);
  border-radius: 4px;
}

.config-content-area::-webkit-scrollbar-thumb:hover {
  background: rgba(99, 102, 241, 0.5);
}

/* 中部：参数预览区域 */
.config-middle-section {
  flex-shrink: 0;
  margin-top: 0.75rem;
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  background: var(--surface-ground);
  overflow: hidden;
}

/* 下部：操作按钮 */
.config-bottom-section {
  flex-shrink: 0;
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 1rem;
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--surface-border);
  overflow: visible;
}

.config-bottom-section .save-preset-btn,
.config-bottom-section .submit-btn {
  flex: 0 0 auto !important;
  width: auto !important;
  min-width: 0 !important;
  height: 2.25rem !important;
}

.submit-hint {
  display: block;
  text-align: center;
  color: var(--text-color-secondary);
  margin-top: 0.5rem;
}

.config-group {
  margin-bottom: 1rem;
}

.config-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: var(--text-color);
}

/* Fieldset样式 */
.config-fieldset {
  margin-bottom: 0.75rem;
}

.config-fieldset :deep(.p-fieldset-legend) {
  font-size: 0.9rem;
  padding: 0.5rem 0.75rem;
}

.config-fieldset :deep(.p-fieldset-content) {
  padding: 0.75rem;
}

/* 配置项网格 */
.config-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}

.config-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.config-item.full-width {
  grid-column: 1 / -1;
  margin-bottom: 0.5rem;
}

.config-item label {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.config-item.checkbox-item {
  flex-direction: row;
  align-items: center;
  gap: 0.5rem;
}

.config-item.checkbox-item label {
  font-size: 0.85rem;
  color: var(--text-color);
}

/* 技术选项复选框 */
.technique-checkboxes {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.5rem;
}

.technique-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.technique-item label {
  font-size: 0.8rem;
  color: var(--text-color);
}

/* 枚举选项 */
.enum-checkboxes {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}

/* 参数预览区域 */
.param-preview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 0.75rem;
  background: var(--surface-card);
  border-bottom: 1px solid var(--surface-border);
}

.param-preview-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
  font-size: 0.85rem;
  color: var(--primary-color);
}

.param-preview-title i {
  font-size: 0.9rem;
}

/* 命令行预览框 */
.cmdline-preview-box {
  background: #1e1e2e;
  padding: 0.75rem 1rem;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.8rem;
  line-height: 1.6;
  overflow-x: auto;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: baseline;
}

.cmdline-prefix {
  color: #89b4fa;
  font-weight: 600;
}

.cmdline-default {
  color: #6c7086;
  font-style: italic;
}

.cmdline-arg {
  display: inline-flex;
  align-items: baseline;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.05);
}

/* 参数类型语法高亮 */
.cmdline-arg.arg-detection {
  background: rgba(249, 115, 22, 0.15);
}

.cmdline-arg.arg-performance {
  background: rgba(34, 197, 94, 0.15);
}

.cmdline-arg.arg-enumerate {
  background: rgba(168, 85, 247, 0.15);
}

.cmdline-arg.arg-network {
  background: rgba(59, 130, 246, 0.15);
}

.cmdline-arg.arg-switch {
  background: rgba(236, 72, 153, 0.15);
}

.cmdline-arg.arg-short {
  background: rgba(251, 191, 36, 0.15);
}

.cmdline-arg :deep(.arg-name) {
  color: #cba6f7;
  font-weight: 500;
}

.cmdline-arg :deep(.arg-equals) {
  color: #6c7086;
  margin: 0 2px;
}

.cmdline-arg :deep(.arg-value) {
  color: #a6e3a1;
}

/* 保留原有的参数预览区域样式（兼容） - 已移除重复定义 */

/* 提交区域 */
.submit-section {
  display: flex;
  gap: 0.75rem;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--surface-border);
}

.save-preset-btn {
  flex-shrink: 0;
}

.submit-btn {
  flex: 1;
  height: 2.75rem;
}

.submit-hint {
  display: block;
  text-align: center;
  color: var(--text-color-secondary);
  margin-top: 0.5rem;
}

/* 对话框 */
.dialog-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.field label {
  font-weight: 500;
}

.w-full {
  width: 100%;
}

/* 配置模式切换区域 - 突出显示 */
.config-mode-switch-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: linear-gradient(135deg, var(--p-primary-50) 0%, var(--p-primary-100) 100%);
  border: 2px solid var(--p-primary-200);
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(99, 102, 241, 0.15);
  margin-bottom: 1rem;
}

.mode-switch-tabs {
  display: flex;
  gap: 8px;
  background: var(--p-content-background);
  padding: 4px;
  border-radius: 10px;
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
}

.mode-tab {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--p-text-muted-color);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
}

.mode-tab i {
  font-size: 16px;
}

.mode-tab:hover:not(.active) {
  background: var(--p-surface-100);
  color: var(--p-text-color);
}

.mode-tab.active {
  background: var(--p-primary-color);
  color: white;
  box-shadow: 0 2px 8px rgba(99, 102, 241, 0.4);
}

.mode-tab.active i {
  color: white;
}

.mode-switch-hint {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--p-primary-600);
  opacity: 0.8;
}

.mode-switch-hint i {
  font-size: 14px;
}

/* 预设模式内容 */
.preset-mode-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  overflow: hidden;
}

/* 预设类型选择器 */
.preset-category-selector {
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.preset-category-selector .selector-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-color-secondary);
}

.preset-category-select :deep(.p-select-label) {
  padding: 0.6rem 0.75rem;
}

.preset-category-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.preset-category-item i {
  font-size: 1rem;
}

/* 预设列表区域 */
.preset-list-area {
  flex: 1;
  overflow-y: auto;
  min-height: 0;
}

.preset-list-container {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem;
  border-radius: 8px;
  min-height: 100%;
}

/* 默认配置背景 - 绿色色调 */
.preset-list-container.preset-default {
  background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(16, 185, 129, 0.03) 100%);
  border: 1px solid rgba(16, 185, 129, 0.2);
}

/* 常用配置背景 - 蓝色色调 */
.preset-list-container.preset-common {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(99, 102, 241, 0.03) 100%);
  border: 1px solid rgba(99, 102, 241, 0.2);
}

/* 历史配置背景 - 橙色色调 */
.preset-list-container.preset-history {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(245, 158, 11, 0.03) 100%);
  border: 1px solid rgba(245, 158, 11, 0.2);
}

/* 预设列表头部 */
.preset-list-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
  font-size: 0.9rem;
  color: var(--text-color);
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--surface-border);
  margin-bottom: 0.25rem;
}

.preset-list-header i {
  font-size: 1rem;
}

.preset-default .preset-list-header i {
  color: #10b981;
}

.preset-common .preset-list-header i {
  color: #6366f1;
}

.preset-history .preset-list-header i {
  color: #f59e0b;
}

.preset-count {
  margin-left: auto;
  font-size: 0.75rem;
  font-weight: 400;
  color: var(--text-color-secondary);
  background: var(--surface-200);
  padding: 0.15rem 0.5rem;
  border-radius: 10px;
}

/* 预设列表内容 */
.preset-list-content {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.preset-card {
  padding: 0.75rem;
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  background: var(--surface-card);
}

.preset-card:hover {
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

/* 默认配置卡片 */
.preset-card-default {
  border-color: rgba(16, 185, 129, 0.3);
}

.preset-card-default:hover {
  border-color: #10b981;
  background: rgba(16, 185, 129, 0.05);
}

.preset-card-default.selected {
  border-color: #10b981;
  background: rgba(16, 185, 129, 0.1);
  box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.2);
}

/* 常用配置卡片 */
.preset-card-common {
  border-color: rgba(99, 102, 241, 0.3);
}

.preset-card-common:hover {
  border-color: #6366f1;
  background: rgba(99, 102, 241, 0.05);
}

.preset-card-common.selected {
  border-color: #6366f1;
  background: rgba(99, 102, 241, 0.1);
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}

/* 历史配置卡片 */
.preset-card-history {
  border-color: rgba(245, 158, 11, 0.3);
}

.preset-card-history:hover {
  border-color: #f59e0b;
  background: rgba(245, 158, 11, 0.05);
}

.preset-card-history.selected {
  border-color: #f59e0b;
  background: rgba(245, 158, 11, 0.1);
  box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
}

.preset-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.25rem;
}

.preset-name {
  font-weight: 500;
  color: var(--text-color);
  font-size: 0.95rem;
}

.preset-card-desc {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
  margin-bottom: 0.25rem;
}

.preset-card-params {
  padding: 0.35rem 0.5rem;
  background: #1e1e2e;
  border-radius: 4px;
  margin-top: 0.35rem;
}

.preset-card-params code {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.75rem;
  color: #89b4fa;
}

.preset-card-params .default-params-hint {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.75rem;
  color: #6c7086;
  font-style: italic;
}

/* 空状态提示 */
.preset-empty-hint {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
  background: var(--surface-50);
  border-radius: 6px;
  border: 1px dashed var(--surface-border);
}

.preset-empty-hint i {
  font-size: 1rem;
  opacity: 0.6;
}

/* 自定义配置模式内容 */
.custom-mode-content {
  flex: 1;
  overflow-y: auto;
}

/* 响应式布局 */
@media (max-width: 1400px) {
  .content-wrapper {
    grid-template-columns: 1fr 1fr;
  }
}

@media (max-width: 1200px) {
  .content-wrapper {
    grid-template-columns: 1fr;
    height: auto;
    min-width: auto;
  }
  
  .left-panel, .right-panel {
    overflow: visible;
    min-width: auto;
  }
  
  .config-card :deep(.p-card-body) {
    max-height: 600px;
  }
}

@media (max-width: 768px) {
  .add-task-container {
    padding: 0.5rem;
  }
  
  .config-grid {
    grid-template-columns: 1fr;
  }
  
  .technique-checkboxes {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .enum-checkboxes {
    grid-template-columns: 1fr;
  }
  
  .mode-switch-tabs {
    flex-direction: column;
  }
  
  .config-mode-switch-bar {
    flex-direction: column;
    gap: 0.75rem;
    align-items: stretch;
  }
  
  .mode-switch-hint {
    justify-content: center;
  }
}
</style>
