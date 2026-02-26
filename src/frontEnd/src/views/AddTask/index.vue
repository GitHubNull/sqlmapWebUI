<template>
  <div class="add-task-container">
    <Card>
      <template #title>
        <div class="page-title-row">
          <span>添加扫描任务</span>
        </div>
      </template>
      <template #content>
        <p class="subtitle">从浏览器DevTools复制HTTP请求报文，转换后提交扫描</p>

        <!-- 报文输入区 -->
        <div class="input-section">
          <div class="section-header">
            <span>报文输入</span>
            <div class="format-indicator" v-if="detectedFormat !== 'unknown'">
              <Tag :severity="formatSeverity">{{ formatDisplayName }}</Tag>
            </div>
          </div>
          <HttpCodeEditor
            v-model="inputContent"
            :placeholder="inputPlaceholder"
            min-height="120px"
            max-height="260px"
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
        </div>

        <!-- HTTP报文编辑区 -->
        <div class="editor-section">
          <div class="section-header">
            <span>HTTP报文编辑</span>
            <Tag severity="info" v-tooltip="'在参数值中添加 * 标记注入点'">
              <i class="pi pi-info-circle"></i> 使用 * 标记注入点
            </Tag>
          </div>
          <HttpCodeEditor
            v-model="rawHttpContent"
            :placeholder="httpPlaceholder"
            min-height="120px"
            max-height="260px"
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
        </div>

        <!-- 配置触发区 -->
        <div class="config-trigger-section">
          <div class="config-summary">
            <div class="config-summary-left">
              <i class="pi pi-sliders-h"></i>
              <span class="config-status-label">当前配置:</span>
              <span class="config-status-text">{{ configStatusText }}</span>
            </div>
            <div class="cmdline-preview-inline" v-if="cmdlineArgs.length > 0">
              <span class="cmdline-prefix-inline">sqlmap</span>
              <span 
                v-for="(arg, index) in cmdlineArgs.slice(0, 6)" 
                :key="index" 
                class="cmdline-arg-inline"
                :class="getArgClass(arg)"
              >{{ arg }}</span>
              <span v-if="cmdlineArgs.length > 6" class="cmdline-more">... (+{{ cmdlineArgs.length - 6 }})</span>
            </div>
            <div class="cmdline-preview-inline cmdline-default-inline" v-else>
              <span class="cmdline-prefix-inline">sqlmap</span>
              <span class="cmdline-hint">(默认参数)</span>
            </div>
          </div>
          <div class="config-trigger-actions">
            <Button 
              label="配置扫描参数" 
              icon="pi pi-cog" 
              severity="secondary"
              outlined
              @click="configDialogVisible = true"
            />
            <Button 
              label="提交扫描任务" 
              icon="pi pi-send" 
              :loading="submitting"
              :disabled="!canSubmit"
              @click="submitTask"
              v-tooltip.top="!canSubmit ? submitDisabledReason : ''"
            />
          </div>
        </div>
        <small class="submit-hint" v-if="!canSubmit && (rawHttpContent.trim() || parsedRequest)">
          {{ submitDisabledReason }}
        </small>
      </template>
    </Card>

    <!-- 扫描配置 Dialog -->
    <Dialog 
      v-model:visible="configDialogVisible"
      header="扫描配置"
      :modal="true"
      :maximizable="true"
      :blockScroll="true"
      :dismissableMask="false"
      :draggable="false"
      :closable="true"
      :style="{ width: '90vw' }"
      :breakpoints="{ '1400px': '95vw', '768px': '98vw' }"
      :contentStyle="{ padding: '1.25rem', overflowY: 'auto', maxHeight: 'calc(90vh - 8rem)' }"
      class="config-dialog"
    >
      <!-- 模式切换栏 -->
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
        <div class="mode-switch-right">
          <div class="mode-switch-hint">
            <i class="pi pi-info-circle"></i>
            <span>{{ configMode === 'preset' ? '选择一个预设配置' : '手动配置扫描参数' }}</span>
          </div>
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
      </div>

      <!-- 配置内容区 -->
      <div class="config-content-area">
        <!-- 预设模式 -->
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
              style="max-width: 300px;"
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
              <div class="preset-list-content preset-grid">
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
              <div class="preset-list-content preset-grid">
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
              <div class="preset-list-content preset-grid">
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

        <!-- 自定义配置模式 -->
        <div v-else class="custom-mode-content">
          <div class="fieldset-grid">
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
                  <Checkbox v-model="currentOptions.smart" inputId="dlg-smart" binary />
                  <label for="dlg-smart">智能检测 (--smart)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.textOnly" inputId="dlg-textOnly" binary />
                  <label for="dlg-textOnly">仅文本比较 (--text-only)</label>
                </div>
              </div>
            </Fieldset>

            <Fieldset legend="注入选项" :toggleable="true" :collapsed="false" class="config-fieldset">
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

            <Fieldset legend="技术选项" :toggleable="true" :collapsed="false" class="config-fieldset">
              <div class="config-item full-width">
                <label>注入技术 (--technique)</label>
                <div class="technique-checkboxes">
                  <div v-for="tech in TECHNIQUE_ITEMS" :key="tech.value" class="technique-item">
                    <Checkbox 
                      v-model="selectedTechniques" 
                      :inputId="'dlg-tech-' + tech.value" 
                      :value="tech.value" 
                    />
                    <label :for="'dlg-tech-' + tech.value">{{ tech.label }}</label>
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

            <Fieldset legend="请求选项" :toggleable="true" :collapsed="false" class="config-fieldset">
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
                  <Checkbox v-model="currentOptions.randomAgent" inputId="dlg-randomAgent" binary />
                  <label for="dlg-randomAgent">随机User-Agent</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.tor" inputId="dlg-tor" binary />
                  <label for="dlg-tor">使用Tor代理</label>
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

            <Fieldset legend="枚举选项" :toggleable="true" :collapsed="false" class="config-fieldset">
              <div class="enum-checkboxes">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getBanner" inputId="dlg-getBanner" binary />
                  <label for="dlg-getBanner">获取Banner (--banner)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getCurrentUser" inputId="dlg-getCurrentUser" binary />
                  <label for="dlg-getCurrentUser">当前用户 (--current-user)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getCurrentDb" inputId="dlg-getCurrentDb" binary />
                  <label for="dlg-getCurrentDb">当前数据库 (--current-db)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.isDba" inputId="dlg-isDba" binary />
                  <label for="dlg-isDba">是否DBA (--is-dba)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getDbs" inputId="dlg-getDbs" binary />
                  <label for="dlg-getDbs">获取所有数据库 (--dbs)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getTables" inputId="dlg-getTables" binary />
                  <label for="dlg-getTables">获取所有表 (--tables)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.getColumns" inputId="dlg-getColumns" binary />
                  <label for="dlg-getColumns">获取所有列 (--columns)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.dumpTable" inputId="dlg-dumpTable" binary />
                  <label for="dlg-dumpTable">导出表数据 (--dump)</label>
                </div>
              </div>
            </Fieldset>

            <Fieldset legend="通用选项" :toggleable="true" :collapsed="false" class="config-fieldset">
              <div class="config-grid">
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.batch" inputId="dlg-batch" binary />
                  <label for="dlg-batch">批处理模式 (--batch)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.forms" inputId="dlg-forms" binary />
                  <label for="dlg-forms">解析表单 (--forms)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.flushSession" inputId="dlg-flushSession" binary />
                  <label for="dlg-flushSession">刷新会话 (--flush-session)</label>
                </div>
                <div class="config-item checkbox-item">
                  <Checkbox v-model="currentOptions.freshQueries" inputId="dlg-freshQueries" binary />
                  <label for="dlg-freshQueries">刷新查询 (--fresh-queries)</label>
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

      <!-- 参数预览区 -->
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

      <!-- Dialog Footer -->
      <template #footer>
        <div class="dialog-footer">
          <Button 
            label="取消" 
            icon="pi pi-times"
            severity="secondary"
            @click="configDialogVisible = false"
          />
          <div class="footer-spacer"></div>
          <Button 
            label="保存为预设" 
            icon="pi pi-save" 
            severity="secondary"
            outlined
            @click="showSavePresetDialog = true"
            :disabled="!canSavePreset"
            v-tooltip.top="!canSavePreset ? '只有自定义配置模式才能保存为预设' : ''"
          />
          <Button 
            label="提交扫描任务" 
            icon="pi pi-send" 
            :loading="submitting"
            :disabled="!canSubmit"
            @click="submitTaskFromDialog"
            v-tooltip.top="!canSubmit ? submitDisabledReason : ''"
          />
        </div>
      </template>
    </Dialog>

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
import Textarea from 'primevue/textarea'

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
import { request as apiRequest } from '@/api/request'

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
const configMode = ref<'preset' | 'custom'>('preset')
const presetCategory = ref<'default' | 'common' | 'history'>('default')
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
const configDialogVisible = ref(false)
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
  if (!rawHttpContent.value.trim() || !parsedRequest.value) {
    return false
  }
  if (configMode.value === 'preset' && !selectedPresetId.value) {
    return false
  }
  return true
})

const canSavePreset = computed(() => {
  return configMode.value === 'custom'
})

const submitDisabledReason = computed(() => {
  if (!rawHttpContent.value.trim() || !parsedRequest.value) {
    return '请先输入并解析HTTP报文'
  }
  if (configMode.value === 'preset' && !selectedPresetId.value) {
    return '请先选择一个预设配置'
  }
  return ''
})

// 配置状态摘要文本
const configStatusText = computed(() => {
  if (configMode.value === 'preset') {
    if (selectedPresetId.value) {
      const all = [
        presetStore.defaultPreset,
        ...presetStore.presetConfigs,
        ...presetStore.historyConfigs
      ]
      const preset = all.find(p => p?.id === selectedPresetId.value)
      return preset ? `预设: ${preset.name}` : '自定义配置'
    }
    return '未选择预设'
  }
  return '自定义配置'
})

// 命令行参数数组
const cmdlineArgs = computed(() => {
  const args: string[] = []
  const opts = currentOptions.value
  const defaults = DEFAULT_SCAN_OPTIONS
  
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

function getArgClass(arg: string): string {
  if (/^-[a-zA-Z]=?/.test(arg)) return 'arg-short'
  if (/^--(level|risk|technique|dbms|os|prefix|suffix|tamper)/.test(arg)) return 'arg-detection'
  if (/^--(threads|timeout|retries|delay|time-sec)/.test(arg)) return 'arg-performance'
  if (/^--(banner|current-user|current-db|is-dba|dbs|tables|columns|dump)/.test(arg)) return 'arg-enumerate'
  if (/^--(proxy|tor|cookie|user-agent|random-agent)/.test(arg)) return 'arg-network'
  if (/^--(batch|smart|text-only|forms|flush-session|fresh-queries)/.test(arg)) return 'arg-switch'
  return 'arg-long'
}

function formatArg(arg: string): string {
  const eqIndex = arg.indexOf('=')
  if (eqIndex > 0) {
    const name = arg.substring(0, eqIndex)
    const value = arg.substring(eqIndex + 1)
    return `<span class="arg-name">${name}</span><span class="arg-equals">=</span><span class="arg-value">${value}</span>`
  }
  return `<span class="arg-name">${arg}</span>`
}

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

async function selectPreset(preset: any) {
  if (!preset || !preset.id) return
  
  try {
    selectedPresetId.value = preset.id
    
    if (preset.options && typeof preset.options === 'object') {
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...preset.options }
    } else {
      await presetStore.selectPreset(preset.id)
      currentOptions.value = { ...DEFAULT_SCAN_OPTIONS, ...presetStore.currentOptions }
    }
    
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
    
    await apiRequest.post('/web/admin/task/add', taskData)
    
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

async function submitTaskFromDialog() {
  await submitTask()
}

onMounted(async () => {
  try {
    await presetStore.loadConfigOptions()
    if (presetStore.defaultPreset) {
      selectedPresetId.value = presetStore.defaultPreset.id || null
    }
  } catch (error) {
    console.error('Failed to load config options:', error)
    currentOptions.value = { ...DEFAULT_SCAN_OPTIONS }
  }
})
</script>

<style scoped>
/* === 页面容器 (与 TaskList 一致) === */
.add-task-container {
  width: 100%;
  margin: 0;
  padding: 0;
}

.page-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.subtitle {
  margin: 0 0 1rem 0;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}

/* === 报文输入/编辑区 === */
.input-section,
.editor-section {
  margin-bottom: 1rem;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
  font-weight: 600;
  font-size: 0.95rem;
  color: var(--text-color);
}

.input-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
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

/* === 配置触发区 === */
.config-trigger-section {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.5rem;
  padding: 1rem 1.25rem;
  background: var(--p-surface-50);
  border: 1px solid var(--surface-border);
  border-radius: 10px;
  margin-top: 0.5rem;
}

.config-summary {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.config-summary-left {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.config-summary-left i {
  color: var(--p-primary-color);
  font-size: 1.1rem;
}

.config-status-label {
  font-weight: 500;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
}

.config-status-text {
  font-weight: 600;
  color: var(--text-color);
  font-size: 0.85rem;
}

.cmdline-preview-inline {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  align-items: baseline;
  padding: 0.4rem 0.65rem;
  background: #1e1e2e;
  border-radius: 6px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.75rem;
  line-height: 1.5;
  overflow: hidden;
}

.cmdline-prefix-inline {
  color: #89b4fa;
  font-weight: 600;
}

.cmdline-arg-inline {
  padding: 1px 4px;
  border-radius: 3px;
  color: #cba6f7;
}

.cmdline-arg-inline.arg-detection { background: rgba(249, 115, 22, 0.15); }
.cmdline-arg-inline.arg-performance { background: rgba(34, 197, 94, 0.15); }
.cmdline-arg-inline.arg-enumerate { background: rgba(168, 85, 247, 0.15); }
.cmdline-arg-inline.arg-network { background: rgba(59, 130, 246, 0.15); }
.cmdline-arg-inline.arg-switch { background: rgba(236, 72, 153, 0.15); }
.cmdline-arg-inline.arg-short { background: rgba(251, 191, 36, 0.15); }

.cmdline-more {
  color: #6c7086;
  font-style: italic;
}

.cmdline-default-inline {
  opacity: 0.7;
}

.cmdline-hint {
  color: #6c7086;
  font-style: italic;
}

.config-trigger-actions {
  display: flex;
  gap: 0.75rem;
  flex-shrink: 0;
}

.submit-hint {
  display: block;
  text-align: right;
  color: var(--text-color-secondary);
  margin-top: 0.5rem;
  font-size: 0.8rem;
}

/* === Dialog 样式 === */
.config-dialog :deep(.p-dialog-content) {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

/* 模式切换栏 */
.config-mode-switch-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: var(--p-surface-100);
  border: 1px solid var(--surface-border);
  border-radius: 12px;
}

.mode-switch-tabs {
  display: flex;
  gap: 8px;
  background: var(--p-content-background);
  padding: 4px;
  border-radius: 10px;
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
}

.mode-tab.active i {
  color: white;
}

.mode-switch-right {
  display: flex;
  align-items: center;
  gap: 0.75rem;
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

/* === 配置内容区 === */
.config-content-area {
  min-height: 0;
}

/* 预设模式 */
.preset-mode-content {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.preset-category-selector {
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

.preset-list-area {
  min-height: 0;
}

.preset-list-container {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem;
  border-radius: 8px;
}

.preset-list-container.preset-default {
  background: rgba(16, 185, 129, 0.08);
  border: 1px solid rgba(16, 185, 129, 0.3);
}

.preset-list-container.preset-common {
  background: rgba(99, 102, 241, 0.08);
  border: 1px solid rgba(99, 102, 241, 0.3);
}

.preset-list-container.preset-history {
  background: rgba(245, 158, 11, 0.08);
  border: 1px solid rgba(245, 158, 11, 0.3);
}

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

.preset-default .preset-list-header i { color: #10b981; }
.preset-common .preset-list-header i { color: #6366f1; }
.preset-history .preset-list-header i { color: #f59e0b; }

.preset-count {
  margin-left: auto;
  font-size: 0.75rem;
  font-weight: 400;
  color: var(--text-color-secondary);
  background: var(--surface-200);
  padding: 0.15rem 0.5rem;
  border-radius: 10px;
}

/* 预设卡片多列网格 */
.preset-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 0.75rem;
}

.preset-card {
  padding: 0.75rem;
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  cursor: pointer;
  background: var(--surface-card);
  transition: border-color 0.2s, background 0.2s;
}

.preset-card:hover {
  border-color: var(--p-primary-color);
}

.preset-card-default { border-color: rgba(16, 185, 129, 0.3); }
.preset-card-default:hover { border-color: #10b981; background: rgba(16, 185, 129, 0.05); }
.preset-card-default.selected { border-color: #10b981; background: rgba(16, 185, 129, 0.1); }

.preset-card-common { border-color: rgba(99, 102, 241, 0.3); }
.preset-card-common:hover { border-color: #6366f1; background: rgba(99, 102, 241, 0.05); }
.preset-card-common.selected { border-color: #6366f1; background: rgba(99, 102, 241, 0.1); }

.preset-card-history { border-color: rgba(245, 158, 11, 0.3); }
.preset-card-history:hover { border-color: #f59e0b; background: rgba(245, 158, 11, 0.05); }
.preset-card-history.selected { border-color: #f59e0b; background: rgba(245, 158, 11, 0.1); }

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

.preset-empty-hint {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
  background: var(--surface-100);
  border-radius: 6px;
  border: 1px dashed var(--surface-border);
  grid-column: 1 / -1;
}

.preset-empty-hint i {
  font-size: 1rem;
  opacity: 0.6;
}

/* === 自定义配置 - Fieldset 多列网格 === */
.custom-mode-content {
  min-height: 0;
}

.fieldset-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.config-fieldset {
  margin-bottom: 0;
}

.config-fieldset :deep(.p-fieldset-legend) {
  font-size: 0.9rem;
  padding: 0.5rem 0.75rem;
}

.config-fieldset :deep(.p-fieldset-content) {
  padding: 0.75rem;
}

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

.enum-checkboxes {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}

/* === 参数预览区 === */
.config-middle-section {
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  background: var(--surface-ground);
  overflow: hidden;
}

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

.cmdline-preview-box {
  background: #1e1e2e;
  padding: 0.75rem 1rem;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.85rem;
  line-height: 1.8;
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

.cmdline-arg.arg-detection { background: rgba(249, 115, 22, 0.15); }
.cmdline-arg.arg-performance { background: rgba(34, 197, 94, 0.15); }
.cmdline-arg.arg-enumerate { background: rgba(168, 85, 247, 0.15); }
.cmdline-arg.arg-network { background: rgba(59, 130, 246, 0.15); }
.cmdline-arg.arg-switch { background: rgba(236, 72, 153, 0.15); }
.cmdline-arg.arg-short { background: rgba(251, 191, 36, 0.15); }

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

/* === Dialog Footer === */
.dialog-footer {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
}

.footer-spacer {
  flex: 1;
}

/* === 保存预设对话框 === */
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

/* === 响应式 === */
@media (max-width: 1400px) {
  .fieldset-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 900px) {
  .fieldset-grid {
    grid-template-columns: 1fr;
  }
  
  .config-trigger-section {
    flex-direction: column;
    align-items: stretch;
  }
  
  .config-trigger-actions {
    justify-content: center;
  }
  
  .preset-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .config-grid {
    grid-template-columns: 1fr;
  }
  
  .technique-checkboxes {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .enum-checkboxes {
    grid-template-columns: 1fr;
  }
  
  .config-mode-switch-bar {
    flex-direction: column;
    gap: 0.75rem;
    align-items: stretch;
  }

  .mode-switch-right {
    justify-content: space-between;
  }
}
</style>
