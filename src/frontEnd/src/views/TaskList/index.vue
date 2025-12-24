<template>
  <div class="task-list-page">
    <Card>
      <template #title>
        <div class="flex-between">
          <span>任务列表</span>
        </div>
      </template>
      <template #content>
        <!-- 搜索过滤面板 -->
        <TaskFilter 
          :filters="taskStore.filters"
          :filteredCount="taskStore.sortedTaskList.length"
          :totalCount="taskStore.taskList.length"
          :loading="taskStore.loading"
          @update:filters="handleFilterChange"
          @refresh="fetchTasks"
        />
        
        <!-- 批量操作栏 -->
        <div v-if="selectedTasks.length > 0" class="batch-actions">
          <div class="batch-info">
            <i class="pi pi-check-circle"></i>
            <span>已选择 {{ selectedTasks.length }} 项</span>
          </div>
          <div class="batch-buttons">
            <Button 
              label="停止选中" 
              icon="pi pi-stop" 
              severity="warning"
              @click="confirmBatchStop"
            />
            <Button 
              label="删除选中" 
              icon="pi pi-trash" 
              severity="danger"
              @click="confirmBatchDelete"
            />
            <Button 
              label="删除全部" 
              icon="pi pi-trash" 
              severity="danger"
              outlined
              @click="confirmDeleteAll"
            />
            <Button 
              label="取消选择" 
              icon="pi pi-times" 
              severity="secondary"
              outlined
              @click="clearSelection"
            />
          </div>
        </div>
        
        <DataTable
          v-model:selection="selectedTasks"
          :value="taskStore.sortedTaskList"
          :loading="taskStore.loading"
          stripedRows
          paginator
          :rows="20"
          :rowsPerPageOptions="[10, 20, 50, 100]"
          :scrollable="true"
          scrollHeight="flex"
          showGridlines
          responsiveLayout="scroll"
          sortMode="single"
          :sortField="taskStore.sortConfig.field"
          :sortOrder="taskStore.sortConfig.order === 'asc' ? 1 : taskStore.sortConfig.order === 'desc' ? -1 : 0"
          @sort="handleSort"
          dataKey="taskid"
          class="fixed-paginator-table"
          resizableColumns
          columnResizeMode="fit"
        >
          <template #empty>
            <div class="empty-table-message">
              <i class="pi pi-inbox"></i>
              <p>暂无扫描任务</p>
              <small>点击左下角「添加任务」按钮创建新任务</small>
            </div>
          </template>
          <template #loading>
            <div class="loading-table-message">
              <i class="pi pi-spin pi-spinner"></i>
              <p>加载中...</p>
            </div>
          </template>
          <!-- 选择列 -->
          <Column selectionMode="multiple" headerStyle="width: 3rem; text-align: center;" bodyStyle="text-align: center;" :exportable="false" frozen />
          <Column field="engineid" header="任务ID" :style="{ minWidth: '80px', maxWidth: '120px' }" sortable>
            <template #body="{ data }">
              <div class="clickable-id" @click="goToTaskConfig(data)" :title="'点击查看任务扫描配置'">
                {{ data.engineid }}
              </div>
            </template>
          </Column>
          <Column field="scanUrl" header="扫描URL" :style="{ minWidth: '250px', maxWidth: '600px' }" sortable>
            <template #body="{ data }">
              <div 
                class="url-cell clickable-url" 
                :title="'点击查看HTTP请求信息'" 
                @click="goToTaskHttpInfo(data)"
              >
                {{ data.scanUrl }}
              </div>
            </template>
          </Column>
          <Column field="host" header="主机" :style="{ minWidth: '120px', maxWidth: '300px' }" sortable />
          <Column field="injected" header="是否存在注入" :style="{ minWidth: '120px', maxWidth: '200px' }" sortable>
            <template #body="{ data }">
              <Tag
                v-if="data.injected !== undefined && data.injected !== null"
                :value="data.injected ? '存在注入' : '无注入'"
                :severity="data.injected ? 'danger' : 'success'"
                :icon="data.injected ? 'pi pi-exclamation-triangle' : 'pi pi-check-circle'"
                :class="{ 'clickable-tag': data.injected }"
                @click="data.injected && goToTaskResults(data)"
                v-tooltip.top="data.injected ? '点击查看扫描结果' : ''"
              />
              <Tag v-else value="未知" severity="secondary" icon="pi pi-question-circle" />
            </template>
          </Column>
          <Column field="status" header="状态" :style="{ minWidth: '100px', maxWidth: '150px' }" sortable>
            <template #body="{ data }">
              <Tag :value="getStatusLabel(data.status)" :severity="getStatusSeverity(data.status)" />
            </template>
          </Column>
          <Column field="createTime" header="创建时间" :style="{ minWidth: '160px', maxWidth: '250px' }" sortable>
            <template #body="{ data }">
              {{ formatDateTime(data.createTime) }}
            </template>
          </Column>
          <Column field="startTime" header="开始执行" :style="{ minWidth: '160px', maxWidth: '250px' }" sortable>
            <template #body="{ data }">
              <span v-if="data.startTime">{{ formatDateTime(data.startTime) }}</span>
              <span v-else class="text-muted">未开始</span>
            </template>
          </Column>
          <Column field="errors" header="错误数" :style="{ minWidth: '80px', maxWidth: '120px' }" sortable>
            <template #body="{ data }">
              <Tag 
                v-if="data.errors > 0" 
                :value="String(data.errors)" 
                severity="danger" 
                icon="pi pi-exclamation-circle"
                class="clickable-tag"
                @click="goToTaskErrors(data)"
                v-tooltip.top="'点击查看错误记录'"
              />
              <span v-else class="text-muted">0</span>
            </template>
          </Column>
          <Column field="logs" header="日志数" :style="{ minWidth: '80px', maxWidth: '120px' }" sortable>
            <template #body="{ data }">
              <Tag 
                v-if="data.logs > 0" 
                :value="String(data.logs)" 
                severity="info" 
                icon="pi pi-file"
                class="clickable-tag"
                @click="goToTaskLogs(data)"
                v-tooltip.top="'点击查看任务日志'"
              />
              <span v-else class="text-muted">0</span>
            </template>
          </Column>
          <Column header="操作" :style="{ minWidth: '120px', maxWidth: '160px' }" frozen alignFrozen="right">
            <template #body="{ data }">
              <div class="action-buttons">
                <Button icon="pi pi-eye" @click="viewTask(data)" text rounded size="small" v-tooltip.top="'查看详情'" />
                <Button icon="pi pi-stop" @click="confirmStopTask(data.taskid)" text rounded size="small" severity="warning" v-if="data.status === 1" v-tooltip.top="'停止任务'" />
                <Button icon="pi pi-trash" @click="confirmDeleteTask(data.taskid)" text rounded size="small" severity="danger" v-tooltip.top="'删除任务'" />
              </div>
            </template>
          </Column>
          
          <!-- 汇总统计行 -->
          <ColumnGroup type="footer">
            <Row>
              <Column footer="汇总" footerStyle="font-weight: bold; text-align: center;" />
              <Column :footer="`共 ${taskStore.taskStats.total} 个任务`" footerStyle="font-weight: bold; text-align: center;" />
              <Column :colspan="2" footer="" />
              <Column footerStyle="text-align: center;">
                <template #footer>
                  <div class="summary-cell">
                    <Tag :value="`存在注入: ${taskStore.taskStats.injectable}`" severity="danger" />
                    <Tag :value="`无注入: ${taskStore.taskStats.nonInjectable}`" severity="success" />
                    <Button 
                      type="button" 
                      icon="pi pi-ellipsis-h" 
                      @click="toggleInjectionPopover" 
                      text 
                      size="small"
                      class="more-btn"
                      v-tooltip.top="'查看完整统计'"
                    />
                    <Popover ref="injectionPopover" appendTo="body" class="stats-popover">
                      <div class="popover-stats">
                        <div class="popover-title">注入统计</div>
                        <div class="popover-items">
                          <Tag :value="`存在注入: ${taskStore.taskStats.injectable}`" severity="danger" />
                          <Tag :value="`无注入: ${taskStore.taskStats.nonInjectable}`" severity="success" />
                          <Tag :value="`未知: ${taskStore.taskStats.unknown}`" severity="secondary" />
                        </div>
                      </div>
                    </Popover>
                  </div>
                </template>
              </Column>
              <Column footerStyle="text-align: center;">
                <template #footer>
                  <div class="summary-cell">
                    <Tag :value="`运行中: ${taskStore.taskStats.running}`" severity="info" />
                    <Tag :value="`已完成: ${taskStore.taskStats.success}`" severity="success" />
                    <Button 
                      type="button" 
                      icon="pi pi-ellipsis-h" 
                      @click="toggleStatusPopover" 
                      text 
                      size="small"
                      class="more-btn"
                      v-tooltip.top="'查看完整统计'"
                    />
                    <Popover ref="statusPopover" appendTo="body" class="stats-popover">
                      <div class="popover-stats">
                        <div class="popover-title">状态统计</div>
                        <div class="popover-items">
                          <Tag :value="`等待中: ${taskStore.taskStats.pending}`" severity="info" />
                          <Tag :value="`运行中: ${taskStore.taskStats.running}`" severity="primary" />
                          <Tag :value="`已完成: ${taskStore.taskStats.success}`" severity="success" />
                          <Tag :value="`失败: ${taskStore.taskStats.failed}`" severity="danger" />
                          <Tag :value="`已停止: ${taskStore.taskStats.stopped}`" severity="warn" />
                          <Tag :value="`已终止: ${taskStore.taskStats.terminated}`" severity="secondary" />
                        </div>
                      </div>
                    </Popover>
                  </div>
                </template>
              </Column>
              <!-- 创建时间、开始执行、错误数、日志数、操作列占位 -->
              <Column footer="" />
              <Column footer="" />
              <Column footer="" />
              <Column footer="" />
              <Column footer="" />
            </Row>
          </ColumnGroup>
        </DataTable>
      </template>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { useTaskStore } from '@/stores/task'
import { TaskStatus } from '@/types/task'
import type { Task, TaskFilters } from '@/types/task'
import { formatDateTime } from '@/utils/format'
import TaskFilter from '@/components/TaskFilter.vue'
import ColumnGroup from 'primevue/columngroup'
import Row from 'primevue/row'
import Popover from 'primevue/popover'

const router = useRouter()
const route = useRoute()
const taskStore = useTaskStore()
const confirm = useConfirm()
const toast = useToast()

// Popover 引用
const injectionPopover = ref()
const statusPopover = ref()

function toggleInjectionPopover(event: Event) {
  injectionPopover.value.toggle(event)
}

function toggleStatusPopover(event: Event) {
  statusPopover.value.toggle(event)
}

// 选中的任务
const selectedTasks = ref<Task[]>([])

onMounted(() => {
  // 从URL参数读取过滤条件
  applyFiltersFromUrl()
  
  // 初始加载任务列表（后续刷新由 WebSocket 通知触发）
  fetchTasks()
  
  // 监听页面可见性，页面重新可见时刷新一次
  document.addEventListener('visibilitychange', handleVisibilityChange)
})

// 从URL参数解析并应用过滤条件
function applyFiltersFromUrl() {
  const filters: TaskFilters = {}
  
  // 解析状态过滤
  const statusParam = route.query.status as string | undefined
  if (statusParam !== undefined) {
    const statusNum = parseInt(statusParam, 10)
    if (!isNaN(statusNum) && statusNum >= 0 && statusNum <= 5) {
      filters.status = statusNum as TaskStatus
    }
  }
  
  // 解析注入状态过滤
  const injectableParam = route.query.injectable as string | undefined
  if (injectableParam === 'injectable' || injectableParam === 'not_injectable' || injectableParam === 'unknown') {
    filters.injectableStatus = injectableParam
  }
  
  // 应用过滤条件
  if (Object.keys(filters).length > 0) {
    taskStore.setFilters(filters)
  }
}

onUnmounted(() => {
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})

async function fetchTasks() {
  await taskStore.fetchTaskList()
}

// 处理页面可见性变化
function handleVisibilityChange() {
  if (!document.hidden) {
    // 页面重新可见，立即刷新一次
    fetchTasks()
  }
}

function getStatusLabel(status: TaskStatus): string {
  const labels = {
    [TaskStatus.PENDING]: '等待中',
    [TaskStatus.RUNNING]: '运行中',
    [TaskStatus.SUCCESS]: '已完成',
    [TaskStatus.FAILED]: '失败',
    [TaskStatus.STOPPED]: '已停止',
    [TaskStatus.TERMINATED]: '已终止',
  }
  return labels[status] || '未知'
}

function getStatusSeverity(status: TaskStatus): string {
  const severities = {
    [TaskStatus.PENDING]: 'info',
    [TaskStatus.RUNNING]: 'primary',
    [TaskStatus.SUCCESS]: 'success',
    [TaskStatus.FAILED]: 'danger',
    [TaskStatus.STOPPED]: 'warn',
    [TaskStatus.TERMINATED]: 'secondary',
  }
  return severities[status] || 'secondary'
}

function viewTask(task: any) {
  router.push(`/tasks/${task.taskid}`)
}

function goToTaskConfig(task: any) {
  router.push(`/tasks/${task.taskid}`)
}

function goToTaskErrors(task: any) {
  // 跳转到任务详情页的错误记录标签页（value="5"）
  router.push({ path: `/tasks/${task.taskid}`, query: { tab: '5' } })
}

function goToTaskLogs(task: any) {
  // 跳转到任务详情页的任务日志标签页（value="4"）
  router.push({ path: `/tasks/${task.taskid}`, query: { tab: '4' } })
}

function goToTaskResults(task: any) {
  // 跳转到任务详情页的扫描结果标签页（value="3"）
  router.push({ path: `/tasks/${task.taskid}`, query: { tab: '3' } })
}

function goToTaskHttpInfo(task: any) {
  // 跳转到任务详情页的HTTP请求信息标签页（value="1"）
  router.push({ path: `/tasks/${task.taskid}`, query: { tab: '1' } })
}

// 确认停止单个任务
function confirmStopTask(taskId: string) {
  confirm.require({
    message: '确定要停止这个任务吗？',
    header: '确认停止',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '停止',
    rejectLabel: '取消',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        await taskStore.stopTask(taskId)
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: '任务已停止',
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '停止任务失败，请重试',
          life: 3000,
        })
      }
    },
  })
}

// 确认删除单个任务
function confirmDeleteTask(taskId: string) {
  confirm.require({
    message: '确定要删除这个任务吗？此操作不可恢复。',
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await taskStore.deleteTask(taskId)
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: '任务已删除',
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '删除任务失败，请重试',
          life: 3000,
        })
      }
    },
  })
}

function handleFilterChange(filters: TaskFilters) {
  // 判断是否为重置操作（空对象或所有字段都是undefined）
  const isReset = Object.keys(filters).length === 0 || 
    Object.values(filters).every(v => v === undefined || v === '' || v === null)
  
  if (isReset) {
    // 重置操作：清空过滤条件并清除URL参数
    taskStore.clearFilters()
    // 清除URL中的过滤参数
    if (route.query.status || route.query.injectable) {
      router.replace({ path: '/tasks', query: {} })
    }
  } else {
    // 普通过滤操作
    taskStore.setFilters(filters)
  }
}

function handleSort(event: any) {
  const order = event.sortOrder === 1 ? 'asc' : event.sortOrder === -1 ? 'desc' : null
  taskStore.setSortConfig({ field: event.sortField, order })
}

// 清空选择
function clearSelection() {
  selectedTasks.value = []
}

// 确认批量停止
function confirmBatchStop() {
  // 过滤出运行中的任务
  const runningTasks = selectedTasks.value.filter(t => t.status === TaskStatus.RUNNING)
  
  if (runningTasks.length === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '选中的任务中没有正在运行的任务',
      life: 3000,
    })
    return
  }
  
  confirm.require({
    message: `确定要停止选中的 ${runningTasks.length} 个运行中的任务吗？`,
    header: '确认停止',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '停止',
    rejectLabel: '取消',
    acceptClass: 'p-button-warning',
    accept: async () => {
      try {
        const taskIds = runningTasks.map(t => t.taskid)
        await taskStore.batchStopTasks(taskIds)
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: `已停止 ${runningTasks.length} 个任务`,
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '停止任务失败，请重试',
          life: 3000,
        })
      }
    },
  })
}

// 确认批量删除
function confirmBatchDelete() {
  // 过滤掉运行中的任务
  const runningTasks = selectedTasks.value.filter(t => t.status === TaskStatus.RUNNING)
  const deletableTasks = selectedTasks.value.filter(t => t.status !== TaskStatus.RUNNING)
  
  if (runningTasks.length > 0) {
    toast.add({
      severity: 'warn',
      summary: '警告',
      detail: `${runningTasks.length} 个运行中的任务已跳过`,
      life: 3000,
    })
  }
  
  if (deletableTasks.length === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '没有可删除的任务',
      life: 3000,
    })
    return
  }
  
  confirm.require({
    message: `确定要删除选中的 ${deletableTasks.length} 个任务吗？此操作不可恢复。`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        const taskIds = deletableTasks.map(t => t.taskid)
        await taskStore.batchDeleteTasks(taskIds)
        selectedTasks.value = []
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: `已删除 ${deletableTasks.length} 个任务`,
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '删除失败，请重试',
          life: 3000,
        })
      }
    },
  })
}

// 确认删除全部
function confirmDeleteAll() {
  const totalCount = taskStore.taskList.length
  
  if (totalCount === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '没有任务可删除',
      life: 3000,
    })
    return
  }
  
  confirm.require({
    message: `这将删除系统中的所有 ${totalCount} 个任务，包括正在运行的任务！

此操作不可恢复，所有扫描结果和日志将永久丢失！

请输入“删除全部”以确认此操作`,
    header: '危险操作！删除所有任务',
    icon: 'pi pi-exclamation-circle',
    acceptLabel: '确认删除',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await taskStore.deleteAllTasks()
        selectedTasks.value = []
        toast.add({
          severity: 'success',
          summary: '成功',
          detail: '已删除所有任务',
          life: 3000,
        })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '错误',
          detail: '删除失败，请重试',
          life: 3000,
        })
      }
    },
  })
}
</script>

<style scoped lang="scss">
@use '@/assets/styles/variables.scss' as *;

.task-list-page {
  width: 100%;  // 占满主内容区域，不限制最大宽度
  margin: 0;
  padding: 0;
  position: relative;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background:
      radial-gradient(circle at 25% 25%, rgba(99, 102, 241, 0.03) 0%, transparent 50%),
      radial-gradient(circle at 75% 75%, rgba(16, 185, 129, 0.03) 0%, transparent 50%),
      url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23f1f5f9' fill-opacity='0.2'%3E%3Cpath d='M20 20.5V18H0v-2h20v2.5zm0 2.5v2.5H0V23h20zm2 0h18v2H22v-2zm0-2.5h18V18H22v2.5z'/%3E%3C/g%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
  }

  > * {
    position: relative;
    z-index: 1;
  }
}

.flex-between {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.batch-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 20px;
  background:
    linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
  border-radius: $border-radius-lg;
  border: 2px solid rgba(99, 102, 241, 0.1);
  box-shadow:
    $shadow-raised,
    inset 0 1px 2px rgba(255, 255, 255, 0.4);
  margin-bottom: 16px;
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
      transparent 0%,
      rgba(255, 255, 255, 0.2) 50%,
      transparent 100%);
    animation: shimmer-batch 3s ease-in-out infinite;
  }

  @media (max-width: 768px) {
    flex-direction: column;
    gap: 16px;
    align-items: stretch;
    padding: 16px 20px;
  }
}

@keyframes shimmer-batch {
  0%, 100% {
    transform: translateX(-100%);
    opacity: 0;
  }
  50% {
    transform: translateX(200%);
    opacity: 1;
  }
}

.batch-info {
  display: flex;
  align-items: center;
  gap: 12px;
  color: $primary-color;
  font-weight: $font-weight-semibold;
  font-size: 16px;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  position: relative;
  z-index: 2;

  i {
    font-size: 20px;
    background: $gradient-primary;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.1));
  }
}

.batch-buttons {
  display: flex;
  gap: 12px;
  position: relative;
  z-index: 2;

  @media (max-width: 768px) {
    flex-direction: column;
    gap: 8px;
  }
}

.url-cell {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 100%;
  padding: 4px 8px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
  transition: $transition-base;

  &:hover {
    background: rgba(99, 102, 241, 0.05);
  }
}

// 可点击URL样式
.clickable-url {
  cursor: pointer;
  color: #6366f1;
  text-decoration: none;
  transition: all 0.2s ease;

  &:hover {
    color: #4f46e5;
    background: rgba(99, 102, 241, 0.1);
    text-decoration: underline;
    transform: translateY(-1px);
    box-shadow: 0 2px 4px rgba(99, 102, 241, 0.2);
    border-radius: 4px;
  }

  &:active {
    transform: translateY(0);
  }
}

.clickable-id {
  cursor: pointer;
  padding: 4px 8px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
  font-weight: 600;
  color: #6366f1;
  border-radius: 4px;
  transition: all 0.3s ease;
  display: inline-block;

  &:hover {
    background: rgba(99, 102, 241, 0.1);
    color: #4f46e5;
    transform: translateY(-1px);
    box-shadow: 0 2px 4px rgba(99, 102, 241, 0.2);
  }

  &:active {
    transform: translateY(0);
    box-shadow: 0 1px 2px rgba(99, 102, 241, 0.2);
  }
}

.action-buttons {
  display: flex;
  gap: 2px;
  justify-content: center;
  align-items: center;
  padding: 0;
}

// 可点击Tag样式
.clickable-tag {
  cursor: pointer;
  transition: all 0.2s ease;

  &:hover {
    transform: translateY(-1px);
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
    filter: brightness(1.1);
  }

  &:active {
    transform: translateY(0);
  }
}

// ==================== DataTable 3D增强 ====================
:deep(.p-datatable) {
  border-radius: $border-radius-lg;
  overflow: hidden;
  box-shadow: $shadow-elevated;
  border: 2px solid rgba(255, 255, 255, 0.3);
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.8) 100%);

  .p-datatable-wrapper {
    overflow-x: auto;
    border-radius: inherit;
  }

  // 表头3D效果
  .p-datatable-thead > tr > th {
    position: sticky;
    top: 0;
    z-index: 10;
    background:
      linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    backdrop-filter: blur(10px);
    border-bottom: 2px solid rgba(99, 102, 241, 0.2);
    box-shadow:
      inset 0 1px 2px rgba(255, 255, 255, 0.4),
      0 2px 4px rgba(0, 0, 0, 0.1);
    color: $text-color;
    font-weight: $font-weight-semibold;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    transition: $transition-base;

    &:hover {
      background:
        linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(59, 130, 246, 0.1) 100%);
      transform: translateY(-1px);
      box-shadow:
        inset 0 1px 2px rgba(255, 255, 255, 0.5),
        0 4px 8px rgba(0, 0, 0, 0.15);
    }
  }

  // 表格行3D效果
  .p-datatable-tbody > tr {
    border-bottom: 1px solid rgba(0, 0, 0, 0.05);
    transition: $transition-base;

    &:hover {
      background:
        linear-gradient(135deg, rgba(99, 102, 241, 0.05) 0%, rgba(59, 130, 246, 0.02) 100%);
      box-shadow:
        0 1px 4px rgba(0, 0, 0, 0.08),
        inset 0 1px 2px rgba(255, 255, 255, 0.3);
    }

    td {
      border-bottom: none;
      padding: 8px 10px;
      vertical-align: middle;
    }
  }

  // 选中行效果
  .p-datatable-tbody > tr.p-selected {
    background:
      linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    box-shadow:
      inset 0 2px 4px rgba(99, 102, 241, 0.1),
      0 2px 8px rgba(99, 102, 241, 0.2);

    &:hover {
      background:
        linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(59, 130, 246, 0.1) 100%);
    }
  }

  .p-column-title {
    white-space: nowrap;
    font-size: 15px;
  }

  // 复选框简洁样式（无3D效果）
  .p-checkbox {
    width: 18px;
    height: 18px;
    margin: 0 auto;
    display: flex !important;
    align-items: center;
    justify-content: center;

    .p-checkbox-box {
      background: #ffffff;
      border: 2px solid #cbd5e1;
      border-radius: 4px;
      width: 18px;
      height: 18px;
      display: inline-flex !important;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
      position: relative;

      &:hover {
        border-color: #94a3b8;
        background: #f8fafc;
      }

      &.p-highlight {
        background: #6366f1 !important;
        border-color: #6366f1 !important;
      }

      &:has(.p-checkbox-icon) {
        background: #6366f1 !important;
        border-color: #6366f1 !important;
      }

      .p-checkbox-icon {
        color: white !important;
        font-size: 12px;
        display: block;
      }

      &.p-focus {
        outline: 2px solid rgba(99, 102, 241, 0.2);
        outline-offset: 2px;
      }
    }

    input {
      opacity: 0;
      position: absolute;
    }
  }

  // 选择列单元格居中
  .p-datatable-thead > tr > th:first-child,
  .p-datatable-tbody > tr > td:first-child {
    text-align: center;
    vertical-align: middle;
    
    .p-checkbox {
      margin: 0 auto;
    }
  }
}

// ==================== 固定分页器样式 ====================
:deep(.fixed-paginator-table) {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 480px);
  min-height: 260px;

  .p-datatable-wrapper {
    flex: 1;
    overflow-y: auto;
    overflow-x: auto;
    min-height: 160px;
  }

  // 空数据提示
  .empty-table-message {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 2rem 1.5rem;
    min-height: 150px;
    color: var(--text-color-secondary);

    i {
      font-size: 4rem;
      margin-bottom: 1rem;
      color: var(--surface-400);
    }

    p {
      font-size: 1.25rem;
      font-weight: 500;
      margin: 0 0 0.5rem 0;
      color: var(--text-color);
    }

    small {
      font-size: 0.875rem;
      color: var(--text-color-secondary);
    }
  }

  // 加载中提示
  .loading-table-message {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem;
    color: var(--text-color-secondary);

    i {
      font-size: 3rem;
      margin-bottom: 1rem;
      color: var(--primary-color);
    }

    p {
      font-size: 1rem;
      margin: 0;
    }
  }

  .p-paginator {
    position: sticky;
    bottom: 0;
    z-index: 5;
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.98) 0%, rgba(248, 250, 252, 0.95) 100%);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    box-shadow:
      0 -2px 8px rgba(0, 0, 0, 0.08),
      inset 0 1px 2px rgba(255, 255, 255, 0.4);
    border-top: 2px solid rgba(99, 102, 241, 0.1);
    padding: 12px 16px;
    margin: 0;
  }

  // 汇总统计行样式
  .p-datatable-tfoot {
    background: linear-gradient(135deg, #e0e7ff 0%, #c7d2fe 50%, #ddd6fe 100%);
    border-top: 3px solid #22c55e;
    border-bottom: 3px solid #22c55e;
    box-shadow: 
      inset 0 2px 4px rgba(34, 197, 94, 0.15),
      0 -2px 8px rgba(34, 197, 94, 0.1),
      0 2px 8px rgba(34, 197, 94, 0.1);
    
    td {
      padding: 14px 8px;
      font-weight: 700;
      color: #1e1b4b;
      border-bottom: none;
      
      &:first-child {
        border-left: 3px solid #22c55e;
      }
      
      &:last-child {
        border-right: 3px solid #22c55e;
      }
    }

    tr {
      background: transparent;

      &:hover {
        background: transparent;
      }
    }
  }
}

// ==================== 汇总单元格样式 ====================
.summary-cell {
  display: flex;
  flex-wrap: nowrap;
  gap: 6px;
  justify-content: center;
  align-items: center;

  :deep(.p-tag) {
    font-size: 12px;
    padding: 4px 8px;
  }

  .more-btn {
    width: 24px;
    height: 24px;
    padding: 0;
    border-radius: 50%;
    background: rgba(99, 102, 241, 0.1);
    color: #6366f1;
    transition: all 0.2s ease;

    &:hover {
      background: rgba(99, 102, 241, 0.2);
      transform: scale(1.1);
    }
  }
}

// ==================== Popover 统计弹出框样式 ====================
.popover-stats {
  padding: 8px;
  min-width: 180px;

  .popover-title {
    font-weight: 600;
    color: #374151;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #e5e7eb;
    font-size: 14px;
  }

  .popover-items {
    display: flex;
    flex-direction: column;
    gap: 8px;

    :deep(.p-tag) {
      font-size: 13px;
      padding: 6px 12px;
      justify-content: flex-start;
    }
  }
}
</style>

<!-- 全局样式 - 统一 Popover 弹出方向 -->
<style lang="scss">
.stats-popover.p-popover {
  // 统一弹出框样式
  box-shadow: 
    0 10px 25px rgba(0, 0, 0, 0.15),
    0 4px 10px rgba(0, 0, 0, 0.1);
  border-radius: 12px;
  border: 1px solid rgba(99, 102, 241, 0.2);
  background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);

  .p-popover-content {
    padding: 12px;
  }

  // 箭头样式
  &::before, &::after {
    border-color: transparent;
  }
}
</style>
