<template>
  <div class="task-detail-page">
    <!-- 页面头部 -->
    <Card>
      <template #title>
        <div class="page-header">
          <div class="header-title">
            <Button
              icon="pi pi-arrow-left"
              @click="router.back()"
              text
              rounded
              v-tooltip.top="'返回列表'"
              class="back-button"
            />
            <span>任务详情</span>
            <Tag
              v-if="task"
              :value="getStatusLabel(task.status)"
              :severity="getStatusSeverity(task.status)"
              class="status-tag"
            />
          </div>
          <div class="header-actions">
            <Button
              icon="pi pi-refresh"
              label="刷新"
              @click="refreshData"
              :loading="loading"
              severity="secondary"
            />
            <Button
              v-if="task && task.status === TaskStatus.RUNNING"
              icon="pi pi-stop"
              label="停止任务"
              severity="warning"
              @click="handleStopTask"
            />
            <Button
              v-if="task && task.status !== TaskStatus.RUNNING"
              icon="pi pi-trash"
              label="删除任务"
              severity="danger"
              @click="handleDeleteTask"
            />
          </div>
        </div>
      </template>
    </Card>

    <!-- 加载状态 -->
    <Card v-if="loading && !task" class="loading-card">
      <template #content>
        <div class="loading-container">
          <ProgressSpinner />
          <p class="loading-text">正在加载任务详情...</p>
        </div>
      </template>
    </Card>

    <!-- 错误状态 -->
    <Card v-else-if="error" class="error-card">
      <template #content>
        <Message severity="error" :closable="false">
          {{ error }}
        </Message>
      </template>
    </Card>

    <!-- 详情内容 -->
    <div v-else-if="task" class="detail-content">
      <Tabs class="detail-tabs" v-model:value="activeTab">
        <TabList>
          <!-- 基础信息 -->
          <Tab value="0">
            <i class="pi pi-info-circle"></i>
            <span>基础信息</span>
          </Tab>

          <!-- HTTP请求信息 -->
          <Tab value="1">
            <i class="pi pi-globe"></i>
            <span>HTTP请求信息</span>
          </Tab>

          <!-- 扫描配置 -->
          <Tab value="2">
            <i class="pi pi-cog"></i>
            <span>扫描配置</span>
          </Tab>

          <!-- 扫描结果 -->
          <Tab value="3" v-if="payloadData && payloadData.length > 0">
            <i class="pi pi-chart-bar"></i>
            <span>扫描结果</span>
          </Tab>

          <!-- 任务日志 -->
          <Tab value="4">
            <i class="pi pi-file"></i>
            <span>任务日志</span>
          </Tab>

          <!-- 错误记录 -->
          <Tab value="5" v-if="errors && errors.length > 0">
            <i class="pi pi-exclamation-triangle"></i>
            <span>错误记录</span>
          </Tab>
        </TabList>

        <TabPanels>
          <!-- 基础信息 -->
          <TabPanel value="0">
            <TaskBasicInfo :task="task" />
          </TabPanel>

          <!-- HTTP请求信息 -->
          <TabPanel value="1">
            <TaskHttpRequest
              :httpInfo="httpInfo"
              :task="task"
              :loadingHttp="loadingHttp"
              :httpRequestSearch="httpRequestSearch"
              :showOnlyMatches="showOnlyMatches"
              :highlightedHttpRequest="highlightedHttpRequest"
              @update:httpRequestSearch="(val: string) => httpRequestSearch = val"
              @update:showOnlyMatches="(val: boolean) => showOnlyMatches = val"
            />
          </TabPanel>

          <!-- 扫描配置 -->
          <TabPanel value="2">
            <TaskOptions
              :task="task"
              :loadingOptions="loadingOptions"
            />
          </TabPanel>

          <!-- 扫描结果 -->
          <TabPanel value="3" v-if="payloadData && payloadData.length > 0">
            <TaskResults
              :payloadData="payloadData"
              :loadingPayload="loadingPayload"
            />
          </TabPanel>

          <!-- 任务日志 -->
          <TabPanel value="4">
            <TaskLogs
              :logs="logs"
              :loadingLogs="loadingLogs"
              :filteredLogs="filteredLogs"
              :searchQuery="logSearchQuery"
              :levelFilter="logLevelFilter"
              :timeRangeFilter="logTimeRangeFilter"
              :sourceFilter="logSourceFilter"
              :useRegex="logUseRegex"
              :caseSensitive="logCaseSensitive"
              :invertMatch="logInvertMatch"
              :showAdvancedSearch="showAdvancedLogSearch"
              @loadLogs="loadLogs"
              @executeSearch="executeLogSearch"
              @resetFilters="resetLogFilters"
              @toggleAdvancedSearch="toggleAdvancedLogSearch"
              @update:searchQuery="(val: string) => logSearchQuery = val"
              @update:levelFilter="(val: string | null) => logLevelFilter = val"
              @update:timeRangeFilter="(val: string) => logTimeRangeFilter = val"
              @update:sourceFilter="(val: string) => logSourceFilter = val"
              @update:useRegex="(val: boolean) => logUseRegex = val"
              @update:caseSensitive="(val: boolean) => logCaseSensitive = val"
              @update:invertMatch="(val: boolean) => logInvertMatch = val"
            />
          </TabPanel>

          <!-- 错误记录 -->
          <TabPanel value="5" v-if="errors && errors.length > 0">
            <TaskErrors :errors="errors" />
          </TabPanel>
        </TabPanels>
      </Tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useTaskDetail } from './composables/useTaskDetail'
import { TaskStatus } from '@/types/task'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import TaskBasicInfo from './components/TaskBasicInfo.vue'
import TaskHttpRequest from './components/TaskHttpRequest.vue'
import TaskOptions from './components/TaskOptions.vue'
import TaskResults from './components/TaskResults.vue'
import TaskLogs from './components/TaskLogs.vue'
import TaskErrors from './components/TaskErrors.vue'

// Tabs选中状态
const activeTab = ref('0')

// 使用组合式函数
const {
  // 状态
  task,
  loading,
  error,
  loadingHttp,
  httpInfo,
  loadingOptions,
  loadingPayload,
  payloadData,
  loadingLogs,
  logs,
  errors,
  httpRequestSearch,
  showOnlyMatches,

  // 日志搜索过滤相关状态
  logSearchQuery,
  logLevelFilter,
  logTimeRangeFilter,
  logSourceFilter,
  logUseRegex,
  logCaseSensitive,
  logInvertMatch,
  showAdvancedLogSearch,

  // 计算属性
  filteredLogs,
  highlightedHttpRequest,

  // 方法
  refreshData,
  getStatusLabel,
  getStatusSeverity,
  // copyLogsToClipboard, // 已移至TaskLogs组件内部实现
  loadLogs,
  executeLogSearch,
  resetLogFilters,
  toggleAdvancedLogSearch,
  handleStopTask,
  handleDeleteTask,
} = useTaskDetail()

// 路由相关
const router = useRouter()
</script>

<style scoped lang="scss">
@import './styles/taskDetail.scss';
</style>