<template>
  <div>
    <div v-if="loadingOptions" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="task?.options" class="options-table-container">
      <table class="options-table">
        <tbody>
          <tr v-for="(value, key) in task.options" :key="key" class="option-row">
            <td class="option-key-cell">{{ formatOptionKey(String(key)) }}</td>
            <td class="option-value-cell">{{ formatOptionValue(value, String(key)) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <span v-else class="text-muted">无配置信息</span>
  </div>
</template>

<script setup lang="ts">
import type { Task } from '@/types/task'

interface Props {
  task?: Task | null
  loadingOptions?: boolean
}

const props = defineProps<Props>()

// 格式化配置键名
function formatOptionKey(key: string): string {
  const keyMap: Record<string, string> = {
    level: '检测级别 (Level)',
    risk: '风险级别 (Risk)',
    technique: '注入技术 (Technique)',
    dbms: '数据库类型 (DBMS)',
    threads: '线程数 (Threads)',
    timeout: '超时时间 (Timeout)',
    retries: '重试次数 (Retries)',
    delay: '延迟时间 (Delay)',
    userAgent: 'User-Agent',
    cookie: 'Cookie',
    headers: '请求头 (Headers)',
    proxy: '代理 (Proxy)',
    randomAgent: '随机User-Agent',
    checkTor: '使用Tor',
    safeUrl: '安全URL',
    safePost: '安全POST',
    safeReq: '安全请求',
  }
  return keyMap[key] || key
}

// 格式化配置值
function formatOptionValue(value: any, _key: string): string {
  if (value === null || value === undefined) {
    return '-'
  }

  if (typeof value === 'boolean') {
    return value ? '是' : '否'
  }

  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : '-'
  }

  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2)
  }

  return String(value)
}
</script>

<style scoped lang="scss">
.loading-small {
  display: flex;
  justify-content: center;
  padding: 20px;
}

.text-muted {
  color: #9ca3af;
  font-style: italic;
  text-align: center;
  padding: 20px;
}

.options-table-container {
  background: linear-gradient(135deg, rgba(248, 250, 252, 0.6) 0%, rgba(241, 245, 249, 0.4) 100%);
  border-radius: 10px;
  padding: 0;
  border: 1px solid rgba(255, 255, 255, 0.5);
  overflow-x: auto;
  max-height: 300px;
  overflow-y: auto;

  &::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  &::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.05);
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(99, 102, 241, 0.3);
    border-radius: 4px;

    &:hover {
      background: rgba(99, 102, 241, 0.5);
    }
  }
}

.options-table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;

  tbody {
    tr {
      border-bottom: 1px solid rgba(99, 102, 241, 0.1);
      transition: all 0.2s ease;

      &:hover {
        background: rgba(99, 102, 241, 0.05);
      }

      &:last-child {
        border-bottom: none;
      }
    }
  }

  td {
    padding: 12px 16px;
    font-size: 14px;
  }
}

.option-key-cell {
  width: 300px;
  font-weight: 600;
  color: #6366f1;
  background: rgba(99, 102, 241, 0.1);
  border-right: 2px solid rgba(99, 102, 241, 0.2);
  white-space: nowrap;

  @media (max-width: 768px) {
    width: auto;
    display: block;
    border-right: none;
    border-bottom: 2px solid rgba(99, 102, 241, 0.2);
  }
}

.option-value-cell {
  color: #1f2937;
  word-break: break-all;
  background: rgba(255, 255, 255, 0.3);

  @media (max-width: 768px) {
    display: block;
  }
}
</style>