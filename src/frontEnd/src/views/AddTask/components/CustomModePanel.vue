<template>
  <div class="custom-mode-content">
    <div class="fieldset-grid">
      <Fieldset legend="检测选项" :toggleable="true" :collapsed="false" class="config-fieldset">
        <div class="config-grid">
          <div class="config-item">
            <label>检测等级 (Level)</label>
            <Select
              :modelValue="options.level"
              @update:modelValue="updateOption('level', $event)"
              :options="LEVEL_OPTIONS"
              optionLabel="label"
              optionValue="value"
              class="w-full"
            />
          </div>
          <div class="config-item">
            <label>风险等级 (Risk)</label>
            <Select
              :modelValue="options.risk"
              @update:modelValue="updateOption('risk', $event)"
              :options="RISK_OPTIONS"
              optionLabel="label"
              optionValue="value"
              class="w-full"
            />
          </div>
        </div>
        <div class="config-grid">
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.smart" @update:modelValue="updateOption('smart', $event)" inputId="dlg-smart" binary />
            <label for="dlg-smart">智能检测 (--smart)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.textOnly" @update:modelValue="updateOption('textOnly', $event)" inputId="dlg-textOnly" binary />
            <label for="dlg-textOnly">仅文本比较 (--text-only)</label>
          </div>
        </div>
      </Fieldset>

      <Fieldset legend="注入选项" :toggleable="true" :collapsed="false" class="config-fieldset">
        <div class="config-grid">
          <div class="config-item">
            <label>目标数据库 (DBMS)</label>
            <Select
              :modelValue="options.dbms"
              @update:modelValue="updateOption('dbms', $event)"
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
              :modelValue="options.os"
              @update:modelValue="updateOption('os', $event)"
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
            :modelValue="options.testParameter"
            @update:modelValue="updateOption('testParameter', $event)"
            placeholder="指定测试参数，如: id,name" 
            class="w-full"
          />
        </div>
        <div class="config-item full-width">
          <label>跳过参数 (--skip)</label>
          <InputText 
            :modelValue="options.skip"
            @update:modelValue="updateOption('skip', $event)"
            placeholder="跳过测试的参数，如: token,csrf" 
            class="w-full"
          />
        </div>
        <div class="config-grid">
          <div class="config-item">
            <label>注入前缀 (--prefix)</label>
            <InputText 
              :modelValue="options.prefix"
              @update:modelValue="updateOption('prefix', $event)"
              placeholder="如: '" 
              class="w-full"
            />
          </div>
          <div class="config-item">
            <label>注入后缀 (--suffix)</label>
            <InputText 
              :modelValue="options.suffix"
              @update:modelValue="updateOption('suffix', $event)"
              placeholder="如: -- -" 
              class="w-full"
            />
          </div>
        </div>
        <div class="config-item full-width">
          <label>Tamper脚本 (--tamper)</label>
          <InputText 
            :modelValue="options.tamper"
            @update:modelValue="updateOption('tamper', $event)"
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
                :modelValue="selectedTechniques"
                @update:modelValue="$emit('update:selectedTechniques', $event)"
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
            :modelValue="options.timeSec"
            @update:modelValue="updateOption('timeSec', $event)"
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
              :modelValue="options.threads"
              @update:modelValue="updateOption('threads', $event)"
              :min="1"
              :max="10"
              showButtons
              class="w-full"
            />
          </div>
          <div class="config-item">
            <label>超时时间 (--timeout)</label>
            <InputNumber
              :modelValue="options.timeout"
              @update:modelValue="updateOption('timeout', $event)"
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
              :modelValue="options.retries"
              @update:modelValue="updateOption('retries', $event)"
              :min="0"
              :max="10"
              showButtons
              class="w-full"
            />
          </div>
          <div class="config-item">
            <label>请求延迟 (--delay)</label>
            <InputNumber
              :modelValue="options.delay"
              @update:modelValue="updateOption('delay', $event)"
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
            <Checkbox :modelValue="options.randomAgent" @update:modelValue="updateOption('randomAgent', $event)" inputId="dlg-randomAgent" binary />
            <label for="dlg-randomAgent">随机User-Agent</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.tor" @update:modelValue="updateOption('tor', $event)" inputId="dlg-tor" binary />
            <label for="dlg-tor">使用Tor代理</label>
          </div>
        </div>
        <div class="config-item full-width">
          <label>代理 (--proxy)</label>
          <InputText 
            :modelValue="options.proxy"
            @update:modelValue="updateOption('proxy', $event)"
            placeholder="如: http://127.0.0.1:8080" 
            class="w-full"
          />
        </div>
      </Fieldset>

      <Fieldset legend="枚举选项" :toggleable="true" :collapsed="false" class="config-fieldset">
        <div class="enum-checkboxes">
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.getBanner" @update:modelValue="updateOption('getBanner', $event)" inputId="dlg-getBanner" binary />
            <label for="dlg-getBanner">获取Banner (--banner)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.getCurrentUser" @update:modelValue="updateOption('getCurrentUser', $event)" inputId="dlg-getCurrentUser" binary />
            <label for="dlg-getCurrentUser">当前用户 (--current-user)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.getCurrentDb" @update:modelValue="updateOption('getCurrentDb', $event)" inputId="dlg-getCurrentDb" binary />
            <label for="dlg-getCurrentDb">当前数据库 (--current-db)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.isDba" @update:modelValue="updateOption('isDba', $event)" inputId="dlg-isDba" binary />
            <label for="dlg-isDba">是否DBA (--is-dba)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.getDbs" @update:modelValue="updateOption('getDbs', $event)" inputId="dlg-getDbs" binary />
            <label for="dlg-getDbs">获取所有数据库 (--dbs)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.getTables" @update:modelValue="updateOption('getTables', $event)" inputId="dlg-getTables" binary />
            <label for="dlg-getTables">获取所有表 (--tables)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.getColumns" @update:modelValue="updateOption('getColumns', $event)" inputId="dlg-getColumns" binary />
            <label for="dlg-getColumns">获取所有列 (--columns)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.dumpTable" @update:modelValue="updateOption('dumpTable', $event)" inputId="dlg-dumpTable" binary />
            <label for="dlg-dumpTable">导出表数据 (--dump)</label>
          </div>
        </div>
      </Fieldset>

      <Fieldset legend="通用选项" :toggleable="true" :collapsed="false" class="config-fieldset">
        <div class="config-grid">
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.batch" @update:modelValue="updateOption('batch', $event)" inputId="dlg-batch" binary />
            <label for="dlg-batch">批处理模式 (--batch)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.forms" @update:modelValue="updateOption('forms', $event)" inputId="dlg-forms" binary />
            <label for="dlg-forms">解析表单 (--forms)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.flushSession" @update:modelValue="updateOption('flushSession', $event)" inputId="dlg-flushSession" binary />
            <label for="dlg-flushSession">刷新会话 (--flush-session)</label>
          </div>
          <div class="config-item checkbox-item">
            <Checkbox :modelValue="options.freshQueries" @update:modelValue="updateOption('freshQueries', $event)" inputId="dlg-freshQueries" binary />
            <label for="dlg-freshQueries">刷新查询 (--fresh-queries)</label>
          </div>
        </div>
        <div class="config-item">
          <label>详细级别 (--verbose)</label>
          <Select
            :modelValue="options.verbose"
            @update:modelValue="updateOption('verbose', $event)"
            :options="VERBOSE_OPTIONS"
            optionLabel="label"
            optionValue="value"
            class="w-full"
          />
        </div>
      </Fieldset>
    </div>
  </div>
</template>

<script setup lang="ts">
import Fieldset from 'primevue/fieldset'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Checkbox from 'primevue/checkbox'
import { 
  LEVEL_OPTIONS, 
  RISK_OPTIONS, 
  DBMS_OPTIONS,
  type ScanOptions
} from '@/types/scanPreset'

interface Props {
  options: ScanOptions
  selectedTechniques: string[]
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'update:options': [options: ScanOptions]
  'update:selectedTechniques': [techniques: string[]]
}>()

// 常量定义
const OS_OPTIONS = [
  { label: '自动检测', value: '' },
  { label: 'Linux', value: 'Linux' },
  { label: 'Windows', value: 'Windows' }
]

const TECHNIQUE_ITEMS = [
  { label: 'B (布尔盲注)', value: 'B' },
  { label: 'E (报错注入)', value: 'E' },
  { label: 'U (联合查询)', value: 'U' },
  { label: 'S (堆叠查询)', value: 'S' },
  { label: 'T (时间盲注)', value: 'T' },
  { label: 'Q (内联查询)', value: 'Q' }
]

const VERBOSE_OPTIONS = [
  { label: '0 (静默)', value: 0 },
  { label: '1 (默认)', value: 1 },
  { label: '2 (调试)', value: 2 },
  { label: '3 (更多调试)', value: 3 },
  { label: '4 (HTTP请求)', value: 4 },
  { label: '5 (HTTP响应头)', value: 5 },
  { label: '6 (HTTP响应体)', value: 6 }
]

// 方法
function updateOption<K extends keyof ScanOptions>(key: K, value: ScanOptions[K]) {
  emit('update:options', { ...props.options, [key]: value })
}
</script>

<style scoped>
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

.w-full {
  width: 100%;
}

@media (max-width: 1400px) {
  .fieldset-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 900px) {
  .fieldset-grid {
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
}
</style>
