<template>
  <div class="session-headers-config">
    <!-- 搜索过滤工具栏 -->
    <Card class="search-filter-card mb-4">
      <template #content>
        <div class="search-filter-toolbar">
          <!-- 搜索区域 -->
          <div class="search-area">
            <IconField iconPosition="left">
              <InputIcon class="pi pi-search" />
              <InputText
                v-model="searchQuery"
                placeholder="搜索Header名称或值..."
                class="search-input"
              />
            </IconField>
          </div>

          <!-- 过滤器区域 -->
          <div class="filter-area">
            <div class="filter-group">
              <label class="filter-label">状态:</label>
              <Select
                v-model="statusFilter"
                :options="statusOptions"
                optionLabel="label"
                optionValue="value"
                placeholder="全部"

                class="filter-dropdown"
                :showClear="true"
              />
            </div>

            <div class="filter-group">
              <label class="filter-label">优先级:</label>
              <Select
                v-model="priorityFilter"
                :options="priorityOptions"
                optionLabel="label"
                optionValue="value"
                placeholder="全部"

                class="filter-dropdown"
                :showClear="true"
              />
            </div>
          </div>

          <!-- 操作按钮区域 -->
          <div class="action-area">
            <Button
              icon="pi pi-filter-slash"
              @click="clearFilters"
              severity="secondary"
              outlined
              v-tooltip.top="'清除过滤器'"
            />
            <Button
              label="单条添加"
              icon="pi pi-plus"
              @click="showAddDialog"
              severity="success"
            />
            <Button
              label="文本导入"
              icon="pi pi-file-edit"
              @click="showTextImportDialog"
              severity="info"
              outlined
            />
            <Button
              label="JSON导入"
              icon="pi pi-code"
              @click="showJsonImportDialog"
              severity="info"
              outlined
            />
            <Button
              label="文件导入"
              icon="pi pi-file-import"
              @click="showFileImportDialog"
              severity="info"
              outlined
            />
            <Button
              label="刷新"
              icon="pi pi-refresh"
              @click="loadSessionHeaders"
              :loading="loading"
              severity="secondary"
              outlined
            />
            <Button
              label="清除所有"
              icon="pi pi-trash"
              @click="confirmClearAll"
              severity="danger"
              outlined
            />
          </div>
        </div>
      </template>
    </Card>

    <!-- 信息提示 -->
    <Message severity="info" :closable="false" class="mb-3">
      <i class="pi pi-info-circle mr-2"></i>
      会话Header仅在当前浏览器会话中有效，关闭浏览器后将自动清除
    </Message>

    <!-- 批量操作工具栏 -->
    <div v-if="selectedSessionHeaders.length > 0" class="batch-actions-toolbar mb-4">
      <Card>
        <template #content>
          <div class="flex align-items-center justify-content-between">
            <div class="flex align-items-center gap-2">
              <i class="pi pi-check-square text-primary text-xl"></i>
              <span class="font-medium">已选择 {{ selectedSessionHeaders.length }} 项</span>
            </div>
            <div class="flex align-items-center gap-2">
              <Button
                label="批量删除"
                icon="pi pi-trash"
                severity="danger"
                @click="confirmBatchDeleteHeaders"
                size="small"
              />
              <Button
                label="批量启用"
                icon="pi pi-eye"
                severity="success"
                @click="batchToggleActiveHeaders(true)"
                size="small"
              />
              <Button
                label="批量禁用"
                icon="pi pi-eye-slash"
                severity="warning"
                @click="batchToggleActiveHeaders(false)"
                size="small"
              />
              <Button
                label="取消选择"
                icon="pi pi-times"
                severity="secondary"
                @click="clearSelection"
                size="small"
                outlined
              />
            </div>
          </div>
        </template>
      </Card>
    </div>

    <!-- Session Headers列表 -->
    <DataTable
      :value="filteredSessionHeaders"
      :loading="loading"
      v-model:selection="selectedSessionHeaders"
      dataKey="id"
      stripedRows
      paginator
      :rows="pageSize"
      :rowsPerPageOptions="[5, 10, 20, 50]"
      sortField="created_at"
      :sortOrder="-1"
      class="session-table"
      :globalFilterFields="['header_name', 'header_value', 'id']"
      responsiveLayout="stack"
      breakpoint="768px"
      :resizableColumns="true"
      columnResizeMode="fit"
    >
      <Column selectionMode="multiple" style="width: 50px"></Column>
      <Column field="id" header="ID" sortable style="width: 80px"></Column>
      <Column field="header_name" header="Header名称" sortable></Column>
      <Column field="header_value" header="Header值">
        <template #body="{ data }">
          <span class="header-value">{{ truncate(data.header_value, 40) }}</span>
        </template>
      </Column>
      <Column field="replace_strategy" header="替换策略" sortable style="width: 120px"></Column>
      <Column field="priority" header="优先级" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.priority" severity="info"></Tag>
        </template>
      </Column>
      <Column field="scope" header="作用域" style="width: 120px">
        <template #body="{ data }">
          <Tag :value="data.scope ? '有作用域' : '全局'" :severity="data.scope ? 'info' : 'secondary'"></Tag>
        </template>
      </Column>
      <Column field="is_active" header="状态" sortable style="width: 100px">
        <template #body="{ data }">
          <Tag :value="data.is_active ? '启用' : '禁用'" :severity="data.is_active ? 'success' : 'danger'"></Tag>
        </template>
      </Column>
      <Column field="created_at" header="创建时间" sortable style="width: 200px">
        <template #body="{ data }">
          <span class="create-time">{{ formatTime(data.created_at) }}</span>
        </template>
      </Column>
      <Column header="操作" style="width: 200px">
        <template #body="{ data }">
          <Button
            icon="pi pi-pencil"
            text
            rounded
            @click="showEditDialog(data)"
            v-tooltip.top="'编辑'"
          />
          <Button
            icon="pi pi-trash"
            text
            rounded
            severity="danger"
            @click="confirmDelete(data)"
            v-tooltip.top="'删除'"
          />
          <Button
            :icon="data.is_active ? 'pi pi-eye-slash' : 'pi pi-eye'"
            text
            rounded
            :severity="data.is_active ? 'warning' : 'success'"
            @click="toggleActive(data)"
            v-tooltip.top="data.is_active ? '禁用' : '启用'"
          />
        </template>
      </Column>
    </DataTable>

    <!-- 批量添加对话框 -->
    <Dialog
      v-model:visible="dialogVisible"
      header="添加Session Headers"
      :style="{
        width: '90vw',
        maxWidth: '1200px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-book text-primary"></i>
              <span>批量添加格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>每行一个Header，格式：</span>
                <code class="format-code">Header-Name: Header-Value</code>
              </div>
            </Message>
          </template>
        </Card>

        <!-- Header输入区域卡片 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-list text-primary"></i>
              <span>Header列表</span>
            </div>
          </template>
          <template #content>
            <div class="input-area">
              <Textarea
                v-model="rawHeaders"
                rows="12"
                placeholder="例如:
Authorization: Bearer your-token-here
X-Custom-Header: custom-value
Cookie: session_id=abc123
X-API-Key: your-api-key
User-Agent: CustomUserAgent/1.0"
                class="uniform-textarea"
                :autoResize="false"
              />
              <div class="input-stats">
                <small class="text-color-secondary">
                  <i class="pi pi-info-circle mr-1"></i>
                  输入行数: {{ rawHeaders.split('\n').filter(line => line.trim()).length }}
                </small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项卡片 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field-horizontal mb-6">
                <label for="priority" class="field-label-left">
                  <i class="pi pi-sort-amount-up mr-2"></i>
                  优先级 (0-100)
                </label>
                <div class="field-content">
                  <InputNumber
                    id="priority"
                    v-model="defaultPriority"
                    :min="0"
                    :max="100"
                    showButtons
                    buttonLayout="horizontal"
                    :step="1"
                    class="uniform-input w-full"
                  />
                  <small class="field-help text-color-secondary">数值越大优先级越高</small>
                </div>
              </div>

              <div class="field-horizontal mb-6">
                <label for="ttl" class="field-label-left">
                  <i class="pi pi-clock mr-2"></i>
                  生存时间 (秒)
                </label>
                <div class="field-content">
                  <InputNumber
                    id="ttl"
                    v-model="defaultTtl"
                    :min="60"
                    :max="86400"
                    showButtons
                    buttonLayout="horizontal"
                    :step="60"
                    class="uniform-input w-full"
                  />
                  <small class="field-help text-color-secondary">默认3600秒(1小时)，最大86400秒(24小时)</small>
                </div>
              </div>
            </div>
          </template>
        </Card>

        <!-- 域控配置 -->
        <ScopeConfigPanel
          v-model="sessionScope"
          title="作用域配置（可选）"
          description="为批量添加的Header统一设置作用域，不配置则对所有请求生效"
          :show-templates="true"
          :show-info="true"
          :show-advanced="false"
        />
      </div>

      <template #footer>
        <Button 
          label="取消" 
          icon="pi pi-times"
          severity="secondary" 
          @click="dialogVisible = false" 
        />
        <Button 
          label="添加" 
          icon="pi pi-check"
          @click="addSessionHeaders" 
          :loading="saving" 
        />
      </template>
    </Dialog>

    <!-- 批量添加对话框 -->
    <Dialog
      v-model:visible="batchDialogVisible"
      header="批量添加Session Headers"
      :style="{
        width: '90vw',
        maxWidth: '900px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-book text-primary"></i>
              <span>批量添加格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>每行一个Header，格式：</span>
                <code class="format-code">Header-Name: Header-Value</code>
              </div>
            </Message>
          </template>
        </Card>

        <!-- Header输入区域卡片 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-list text-primary"></i>
              <span>Header列表</span>
            </div>
          </template>
          <template #content>
            <div class="input-area">
              <Textarea
                v-model="batchRawHeaders"
                rows="12"
                placeholder="例如:
Authorization: Bearer your-token-here
X-Custom-Header: custom-value
Cookie: session_id=abc123
X-API-Key: your-api-key
User-Agent: CustomUserAgent/1.0"
                class="headers-textarea"
                :autoResize="false"
              />
              <div class="input-stats">
                <small class="text-color-secondary">
                  <i class="pi pi-info-circle mr-1"></i>
                  输入行数: {{ batchRawHeaders.split('\n').filter(line => line.trim()).length }}
                </small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项卡片 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field-horizontal mb-6">
                <label for="batch_priority" class="field-label-left">
                  <i class="pi pi-sort-numeric-down mr-2"></i>
                  默认优先级
                </label>
                <div class="field-content">
                  <InputNumber
                    id="batch_priority"
                    v-model="defaultPriority"
                    :min="0"
                    :max="100"
                    suffix=" 分"
                    class="w-full"
                  />
                  <small class="field-help text-color-secondary">0-100，越大优先级越高</small>
                </div>
              </div>

              <div class="field-horizontal mb-6">
                <label for="batch_ttl" class="field-label-left">
                  <i class="pi pi-clock mr-2"></i>
                  默认过期时间
                </label>
                <div class="field-content">
                  <InputNumber
                    id="batch_ttl"
                    v-model="defaultTtl"
                    :min="60"
                    :max="86400"
                    suffix=" 秒"
                    class="w-full"
                  />
                  <small class="field-help text-color-secondary">60-86400秒（1分钟-24小时）</small>
                </div>
              </div>
            </div>
          </template>
        </Card>

        <!-- 域控配置 -->
        <ScopeConfigPanel
          v-model="sessionScope"
          title="作用域配置（可选）"
          description="为批量添加的Header统一设置作用域，不配置则对所有请求生效"
          :show-templates="true"
          :show-info="true"
          :show-advanced="false"
        />
      </div>

      <template #footer>
        <Button 
          label="取消" 
          icon="pi pi-times"
          severity="secondary" 
          @click="batchDialogVisible = false" 
        />
        <Button 
          label="添加" 
          icon="pi pi-check"
          @click="handleBatchAdd" 
          :loading="saving" 
        />
      </template>
    </Dialog>

    <!-- 文件导入对话框 -->
    <Dialog
      v-model:visible="fileImportDialogVisible"
      header="从文件导入Session Headers"
      :style="{
        width: '90vw',
        maxWidth: '900px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-book text-primary"></i>
              <span>文件格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div>
                <div class="mb-2">
                  <i class="pi pi-info-circle mr-2"></i>
                  支持的文件格式：
                </div>
                <ul class="ml-4">
                  <li>文本文件 (.txt)：每行一个Header，格式为 <code class="format-code">Header-Name: Header-Value</code></li>
                  <li>JSON文件 (.json)：对象数组格式，每个对象包含header_name和header_value字段</li>
                </ul>
              </div>
            </Message>
          </template>
        </Card>

        <!-- 文件上传区域 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-upload text-primary"></i>
              <span>选择文件</span>
            </div>
          </template>
          <template #content>
            <div class="file-upload-area">
              <!-- 文件选择按钮 -->
              <div class="mb-4">
                <Button
                  label="选择文件"
                  icon="pi pi-folder-open"
                  @click="selectFile"
                  severity="secondary"
                  outlined
                  class="mb-3"
                />
                <input
                  type="file"
                  ref="fileInput"
                  accept=".txt,.json"
                  @change="handleFileSelect"
                  class="file-input"
                  style="display: none"
                />
                <div class="field-help text-color-secondary">
                  支持 .txt 和 .json 格式文件
                </div>
              </div>

              <!-- 文件预览区域 -->
              <div class="file-preview" v-if="fileContent">
                <div class="file-preview-header mb-3">
                  <span class="font-semibold">文件内容预览：</span>
                </div>
                <Textarea
                  v-model="fileContent"
                  rows="10"
                  class="headers-textarea"
                  :autoResize="false"
                  readonly
                />
              </div>
            </div>
          </template>
        </Card>

        </div>

      <template #footer>
        <Button 
          label="取消" 
          icon="pi pi-times"
          severity="secondary" 
          @click="fileImportDialogVisible = false" 
        />
        <Button 
          label="导入" 
          icon="pi pi-check"
          @click="handleFileImport" 
          :loading="saving"
          :disabled="!fileContent" 
        />
      </template>
    </Dialog>

    <!-- 编辑对话框 -->
    <Dialog
      v-model:visible="editDialogVisible"
      header="编辑Session Header"
      :style="{
        width: '90vw',
        maxWidth: '800px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 基本信息 -->
        <Card class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-pencil text-primary"></i>
              <span>基本信息</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-4">
                <label for="edit_header_name" class="block mb-2 font-medium">
                  Header名称 <span class="text-red-500">*</span>
                </label>
                <InputText
                  id="edit_header_name"
                  v-model="editFormData.header_name"
                  class="uniform-input w-full"
                  placeholder="例如: Authorization"
                />
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="edit_replace_strategy" class="block mb-2 font-medium">
                  替换策略
                </label>
                <Select
                  id="edit_replace_strategy"
                  v-model="editFormData.replace_strategy"
                  :options="replaceStrategyOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="选择替换策略"
                  class="uniform-input w-full"
                />
              </div>

              <div class="field col-12 mb-4">
                <label for="edit_header_value" class="block mb-2 font-medium">
                  Header值 <span class="text-red-500">*</span>
                </label>
                <Textarea
                  id="edit_header_value"
                  v-model="editFormData.header_value"
                  rows="3"
                  placeholder="例如: Bearer your-token-here"
                  class="uniform-textarea w-full"
                  :autoResize="false"
                />
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项 -->
        <Card class="mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="formgrid grid p-fluid">
              <div class="field col-12 md:col-6 mb-4">
                <label for="edit_priority" class="block mb-2 font-medium">
                  优先级 (0-100)
                </label>
                <InputNumber
                  id="edit_priority"
                  v-model="editFormData.priority"
                  :min="0"
                  :max="100"
                  showButtons
                  buttonLayout="horizontal"
                  :step="1"
                  class="uniform-input w-full"
                />
                <small class="text-color-secondary mt-1 block">数值越大优先级越高</small>
              </div>

              <div class="field col-12 md:col-6 mb-4">
                <label for="edit_ttl" class="block mb-2 font-medium">
                  生存时间 (秒)
                </label>
                <InputNumber
                  id="edit_ttl"
                  v-model="editFormData.ttl"
                  :min="60"
                  :max="86400"
                  showButtons
                  buttonLayout="horizontal"
                  :step="60"
                  class="uniform-input w-full"
                />
                <small class="text-color-secondary mt-1 block">默认3600秒(1小时)，最大86400秒(24小时)</small>
              </div>

              <div class="field col-12 mb-4">
                <div class="flex align-items-center gap-3">
                  <Checkbox
                    id="edit_is_active"
                    v-model="editFormData.is_active"
                    binary
                  />
                  <label for="edit_is_active" class="font-medium cursor-pointer">
                    启用此Header
                  </label>
                </div>
                <small class="text-color-secondary mt-1 block">禁用后此Header不会生效</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 作用域配置 -->
        <ScopeConfigPanel
          v-model="editFormData.scope"
          title="作用域配置（可选）"
          description="配置Header的生效范围，不配置则对所有请求生效"
          :show-templates="true"
          :show-info="true"
          :show-advanced="false"
        />
      </div>

      <template #footer>
        <Button
          label="取消"
          icon="pi pi-times"
          severity="secondary"
          @click="editDialogVisible = false"
        />
        <Button
          label="保存"
          icon="pi pi-check"
          @click="updateHeader"
          :loading="saving"
        />
      </template>
    </Dialog>

    <!-- 文本导入对话框 -->
    <Dialog
      v-model:visible="textImportDialogVisible"
      header="文本导入Session Headers"
      :style="{
        width: '90vw',
        maxWidth: '900px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-file-edit text-primary"></i>
              <span>文本导入格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div class="flex align-items-center gap-2">
                <i class="pi pi-info-circle"></i>
                <span>每行一个Header，格式：</span>
                <code class="format-code">Header-Name: Header-Value</code>
              </div>
            </Message>
          </template>
        </Card>

        <!-- 文本输入区域卡片 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-list text-primary"></i>
              <span>Header列表</span>
            </div>
          </template>
          <template #content>
            <div class="input-area">
              <Textarea
                v-model="fileContent"
                rows="12"
                class="uniform-textarea"
                placeholder="例如:
Authorization: Bearer your-token-here
X-Custom-Header: custom-value
Cookie: session_id=abc123
X-API-Key: your-api-key
User-Agent: CustomUserAgent/1.0"
              />
              <div class="input-stats mt-2">
                <small class="text-color-secondary">输入行数: {{ fileContent.split('\n').filter(line => line.trim()).length }}</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项卡片 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="field-horizontal mb-6">
              <label for="priority" class="field-label-left">
                <i class="pi pi-sort-amount-up mr-2"></i>
                默认优先级
              </label>
              <div class="field-content">
                <InputNumber
                  id="priority"
                  v-model="defaultPriority"
                  class="w-full"
                  :min="0"
                  :max="100"
                />
                <small class="field-help text-color-secondary">0-100，数值越大优先级越高</small>
              </div>
            </div>

            <div class="field-horizontal mb-6">
              <label for="ttl" class="field-label-left">
                <i class="pi pi-clock mr-2"></i>
                默认过期时间
              </label>
              <div class="field-content">
                <InputNumber
                  id="ttl"
                  v-model="defaultTtl"
                  class="w-full"
                  :min="60"
                  :max="86400"
                  suffix=" 秒"
                />
                <small class="field-help text-color-secondary">60-86400秒（1分钟-24小时）</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 作用域配置 -->
        <ScopeConfigPanel
          v-model="sessionScope"
          :title="'作用域配置（可选）'"
          :description="'为导入的Header统一设置作用域，不配置则对所有请求生效'"
          :show-templates="true"
          :show-info="true"
          :show-advanced="false"
        />
      </div>

      <template #footer>
        <Button
          label="取消"
          icon="pi pi-times"
          severity="secondary"
          @click="textImportDialogVisible = false"
        />
        <Button
          label="导入"
          icon="pi pi-check"
          @click="handleTextImport"
          :loading="saving"
        />
      </template>
    </Dialog>

    <!-- JSON导入对话框 -->
    <Dialog
      v-model:visible="jsonImportDialogVisible"
      header="JSON导入Session Headers"
      :style="{
        width: '90vw',
        maxWidth: '900px',
        maxHeight: '85vh'
      }"
      modal
      class="session-dialog"
    >
      <div class="dialog-content">
        <!-- 使用说明卡片 -->
        <Card class="info-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-code text-primary"></i>
              <span>JSON导入格式说明</span>
            </div>
          </template>
          <template #content>
            <Message severity="info" :closable="false">
              <div class="flex flex-col gap-2">
                <div><i class="pi pi-info-circle mr-2"></i>JSON格式，对象数组：</div>
                <code class="format-code">
[
  {
    "header_name": "Authorization",
    "header_value": "Bearer token123",
    "replace_strategy": "REPLACE",
    "priority": 80
  }
]
                </code>
              </div>
            </Message>
          </template>
        </Card>

        <!-- JSON输入区域卡片 -->
        <Card class="input-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-code text-primary"></i>
              <span>JSON数据</span>
            </div>
          </template>
          <template #content>
            <div class="input-area">
              <Textarea
                v-model="fileContent"
                rows="12"
                class="uniform-textarea"
                placeholder='[
  {
    "header_name": "Authorization",
    "header_value": "Bearer your-token-here",
    "replace_strategy": "REPLACE",
    "priority": 80
  }
]'
              />
              <div class="input-stats mt-2">
                <small class="text-color-secondary">JSON数据长度: {{ fileContent.length }} 字符</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 配置选项卡片 -->
        <Card class="config-card mb-4">
          <template #title>
            <div class="flex align-items-center gap-2">
              <i class="pi pi-cog text-primary"></i>
              <span>配置选项</span>
            </div>
          </template>
          <template #content>
            <div class="field-horizontal mb-6">
              <label for="priority" class="field-label-left">
                <i class="pi pi-sort-amount-up mr-2"></i>
                默认优先级
              </label>
              <div class="field-content">
                <InputNumber
                  id="priority"
                  v-model="defaultPriority"
                  class="w-full"
                  :min="0"
                  :max="100"
                />
                <small class="field-help text-color-secondary">当JSON中未指定优先级时使用</small>
              </div>
            </div>

            <div class="field-horizontal mb-6">
              <label for="ttl" class="field-label-left">
                <i class="pi pi-clock mr-2"></i>
                默认过期时间
              </label>
              <div class="field-content">
                <InputNumber
                  id="ttl"
                  v-model="defaultTtl"
                  class="w-full"
                  :min="60"
                  :max="86400"
                  suffix=" 秒"
                />
                <small class="field-help text-color-secondary">当JSON中未指定过期时间时使用</small>
              </div>
            </div>
          </template>
        </Card>

        <!-- 作用域配置 -->
        <ScopeConfigPanel
          v-model="sessionScope"
          :title="'作用域配置（可选）'"
          :description="'为导入的Header统一设置作用域，不配置则对所有请求生效'"
          :show-templates="true"
          :show-info="true"
          :show-advanced="false"
        />
      </div>

      <template #footer>
        <Button
          label="取消"
          icon="pi pi-times"
          severity="secondary"
          @click="jsonImportDialogVisible = false"
        />
        <Button
          label="导入"
          icon="pi pi-check"
          @click="handleJsonImport"
          :loading="saving"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import Select from 'primevue/select'
import ScopeConfigPanel from './ScopeConfigPanel.vue'
import {
  getSessionHeaders,
  setSessionHeaders,
  deleteSessionHeader,
  updateSessionHeader,
  clearSessionHeaders,
} from '@/api/headerRule'
import type { SessionHeader, HeaderScope } from '@/types/headerRule'
import { ReplaceStrategy } from '@/types/headerRule'

const toast = useToast()
const confirm = useConfirm()

const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const batchDialogVisible = ref(false)
const fileImportDialogVisible = ref(false)
const textImportDialogVisible = ref(false) // 文本导入对话框可见性
const jsonImportDialogVisible = ref(false) // JSON导入对话框可见性
const editDialogVisible = ref(false) // 编辑对话框可见性
const sessionHeaders = ref<any[]>([])
const selectedSessionHeaders = ref<any[]>([]) // 多选
const rawHeaders = ref('')
const batchRawHeaders = ref('')
const fileContent = ref('')
const defaultPriority = ref(50)
const defaultTtl = ref(3600) // 默认1小时

// 编辑相关状态
const editingHeader = ref<any>(null) // 当前编辑的Header
const editFormData = ref({
  header_name: '',
  header_value: '',
  replace_strategy: 'REPLACE' as any,
  priority: 50,
  is_active: true,
  ttl: 3600,
  scope: null as any
})

// 搜索和过滤相关
const searchQuery = ref('')
const statusFilter = ref<string | null>(null)
const priorityFilter = ref<string | null>(null)
const pageSize = ref(10)
const sessionScope = ref<HeaderScope | null>(null) // Session Header作用域配置
const fileInput = ref<HTMLInputElement | null>(null) // 文件输入引用

// 过滤选项
const statusOptions = [
  { label: '有效', value: 'valid' },
  { label: '已过期', value: 'expired' },
]

const priorityOptions = [
  { label: '高 (80-100)', value: 'high' },
  { label: '中 (50-79)', value: 'medium' },
  { label: '低 (0-49)', value: 'low' },
]

// 替换策略选项
const replaceStrategyOptions = [
  { label: '完全替换', value: ReplaceStrategy.REPLACE },
  { label: '追加', value: ReplaceStrategy.APPEND },
  { label: '前置', value: ReplaceStrategy.PREPEND },
  { label: '条件性替换', value: ReplaceStrategy.CONDITIONAL },
  { label: '存在则替换，不存在则新增', value: ReplaceStrategy.UPSERT },
]

onMounted(() => {
  loadSessionHeaders()
})

async function loadSessionHeaders() {
  loading.value = true
  try {
    const res = await getSessionHeaders()
    if (res.success) {
      sessionHeaders.value = res.data.headers || []
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '加载失败',
      detail: error.message || '加载Session Headers失败',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

function showAddDialog() {
  rawHeaders.value = ''
  defaultPriority.value = 50
  defaultTtl.value = 3600
  dialogVisible.value = true
}

function showFileImportDialog() {
  fileContent.value = ''
  fileImportDialogVisible.value = true
}

// 文件选择方法
function selectFile() {
  fileInput.value?.click()
}

function showTextImportDialog() {
  fileContent.value = ''
  textImportDialogVisible.value = true
}

function showJsonImportDialog() {
  fileContent.value = ''
  jsonImportDialogVisible.value = true
}

async function addSessionHeaders() {
  if (!rawHeaders.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请输入Header内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    // 解析Headers
    const lines = rawHeaders.value.split('\n').filter((line) => line.trim())
    const headers: SessionHeader[] = []

    for (const line of lines) {
      const [name, ...valueParts] = line.split(':')
      if (name && valueParts.length > 0) {
        headers.push({
          header_name: name.trim(),
          header_value: valueParts.join(':').trim(),
          priority: defaultPriority.value,
          ttl: defaultTtl.value,
          scope: sessionScope.value, // 添加作用域配置
        })
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未能解析出有效的Header',
        life: 3000,
      })
      return
    }

    await setSessionHeaders({ headers })
    toast.add({
      severity: 'success',
      summary: '添加成功',
      detail: `成功添加 ${headers.length} 个Session Header`,
      life: 3000,
    })

    dialogVisible.value = false
    await loadSessionHeaders()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '添加失败',
      detail: error.message || '添加Session Headers失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

// 文本导入处理
async function handleTextImport() {
  if (!fileContent.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '输入为空',
      detail: '请输入要导入的文本内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    // 解析文本格式
    const lines = fileContent.value.split('\n').filter(line => line.trim())
    const headers = []

    for (const line of lines) {
      const trimmedLine = line.trim()
      if (trimmedLine && trimmedLine.includes(':')) {
        const [name, ...valueParts] = trimmedLine.split(':')
        if (name && valueParts.length > 0) {
          headers.push({
            header_name: name.trim(),
            header_value: valueParts.join(':').trim(),
            priority: defaultPriority.value,
            ttl: defaultTtl.value,
            scope: sessionScope.value
          })
        }
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未找到有效的Header格式，请检查输入格式',
        life: 3000,
      })
      return
    }

    // 调用相同的导入逻辑
    const res = await setSessionHeaders({ headers })
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '导入成功',
        detail: `成功导入 ${headers.length} 个Header`,
        life: 3000,
      })
      textImportDialogVisible.value = false
      fileContent.value = ''
      await loadSessionHeaders()
    } else {
      throw new Error(res.message || '导入失败')
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '导入失败',
      detail: error.message || '文本导入失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

// JSON导入处理
async function handleJsonImport() {
  if (!fileContent.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '输入为空',
      detail: '请输入要导入的JSON内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    // 解析JSON格式
    const jsonData = JSON.parse(fileContent.value)

    if (!Array.isArray(jsonData)) {
      throw new Error('JSON格式错误：必须是对象数组')
    }

    const headers = []
    for (const item of jsonData) {
      if (item.header_name && item.header_value) {
        headers.push({
          header_name: item.header_name,
          header_value: item.header_value,
          priority: item.priority || defaultPriority.value,
          ttl: item.ttl || defaultTtl.value,
          scope: item.scope || sessionScope.value
        })
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: 'JSON中未找到有效的Header数据',
        life: 3000,
      })
      return
    }

    // 调用相同的导入逻辑
    const res = await setSessionHeaders({ headers })
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '导入成功',
        detail: `成功导入 ${headers.length} 个Header`,
        life: 3000,
      })
      jsonImportDialogVisible.value = false
      fileContent.value = ''
      await loadSessionHeaders()
    } else {
      throw new Error(res.message || '导入失败')
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '导入失败',
      detail: 'JSON导入失败：' + error.message,
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

async function handleBatchAdd() {
  if (!batchRawHeaders.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请输入Header内容',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    // 解析Headers
    const lines = batchRawHeaders.value.split('\n').filter((line) => line.trim())
    const headers: SessionHeader[] = []

    for (const line of lines) {
      const [name, ...valueParts] = line.split(':')
      if (name && valueParts.length > 0) {
        headers.push({
          header_name: name.trim(),
          header_value: valueParts.join(':').trim(),
          priority: defaultPriority.value,
          ttl: defaultTtl.value,
          scope: sessionScope.value,
        })
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未能解析出有效的Header',
        life: 3000,
      })
      return
    }

    await setSessionHeaders({ headers })
    toast.add({
      severity: 'success',
      summary: '批量添加成功',
      detail: `成功添加 ${headers.length} 个Session Header`,
      life: 3000,
    })

    batchDialogVisible.value = false
    await loadSessionHeaders()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '批量添加失败',
      detail: error.message || '批量添加Session Headers失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function handleFileSelect(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  if (!file) return

  const reader = new FileReader()
  reader.onload = (e) => {
    fileContent.value = e.target?.result as string
  }
  reader.readAsText(file)
}

async function handleFileImport() {
  if (!fileContent.value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请选择文件',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    let headers: SessionHeader[] = []

    // 尝试解析为JSON
    try {
      const jsonData = JSON.parse(fileContent.value)
      if (Array.isArray(jsonData)) {
        headers = jsonData.map(item => ({
          header_name: item.header_name || item.name,
          header_value: item.header_value || item.value,
          priority: item.priority || defaultPriority.value,
          ttl: item.ttl || defaultTtl.value,
          scope: item.scope || sessionScope.value,
        }))
      }
    } catch {
      // JSON解析失败，尝试作为文本文件解析
      const lines = fileContent.value.split('\n').filter((line) => line.trim())
      for (const line of lines) {
        const [name, ...valueParts] = line.split(':')
        if (name && valueParts.length > 0) {
          headers.push({
            header_name: name.trim(),
            header_value: valueParts.join(':').trim(),
            priority: defaultPriority.value,
            ttl: defaultTtl.value,
            scope: sessionScope.value,
          })
        }
      }
    }

    if (headers.length === 0) {
      toast.add({
        severity: 'warn',
        summary: '解析失败',
        detail: '未能从文件中解析出有效的Header',
        life: 3000,
      })
      return
    }

    await setSessionHeaders({ headers })
    toast.add({
      severity: 'success',
      summary: '导入成功',
      detail: `成功导入 ${headers.length} 个Session Header`,
      life: 3000,
    })

    fileImportDialogVisible.value = false
    fileContent.value = ''
    await loadSessionHeaders()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '导入失败',
      detail: error.message || '导入Session Headers失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function confirmClearAll() {
  if (sessionHeaders.value.length === 0) {
    toast.add({
      severity: 'info',
      summary: '提示',
      detail: '当前没有Session Headers',
      life: 3000,
    })
    return
  }

  confirm.require({
    message: '确定要清除所有Session Headers吗？',
    header: '确认清除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '清除',
    rejectLabel: '取消',
    accept: async () => {
      try {
        await clearSessionHeaders()
        toast.add({
          severity: 'success',
          summary: '清除成功',
          detail: 'Session Headers已清除',
          life: 3000,
        })
        await loadSessionHeaders()
      } catch (error: any) {
        toast.add({
          severity: 'error',
          summary: '清除失败',
          detail: error.message || '清除Session Headers失败',
          life: 3000,
        })
      }
    },
  })
}

function formatTime(timeStr: string) {
  if (!timeStr) return '-'
  return new Date(timeStr).toLocaleString('zh-CN')
}

function truncate(text: string, length: number) {
  if (text.length <= length) return text
  return text.substring(0, length) + '...'
}

// 计算属性：过滤后的Session Headers
const filteredSessionHeaders = computed(() => {
  let filtered = sessionHeaders.value

  // 搜索过滤
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(header =>
      header.header_name.toLowerCase().includes(query) ||
      header.header_value.toLowerCase().includes(query)
    )
  }

  // 状态过滤（有效/过期）
  if (statusFilter.value) {
    const now = new Date()
    if (statusFilter.value === 'valid') {
      filtered = filtered.filter(header => new Date(header.expires_at) > now)
    } else if (statusFilter.value === 'expired') {
      filtered = filtered.filter(header => new Date(header.expires_at) <= now)
    }
  }

  // 优先级过滤
  if (priorityFilter.value) {
    if (priorityFilter.value === 'high') {
      filtered = filtered.filter(header => (header.priority || 50) >= 80)
    } else if (priorityFilter.value === 'medium') {
      filtered = filtered.filter(header => {
        const priority = header.priority || 50
        return priority >= 50 && priority < 80
      })
    } else if (priorityFilter.value === 'low') {
      filtered = filtered.filter(header => (header.priority || 50) < 50)
    }
  }

  return filtered
})

// 清除过滤器
function clearFilters() {
  searchQuery.value = ''
  statusFilter.value = null
  priorityFilter.value = null
}

// 编辑Session Header
function showEditDialog(header: any) {
  editingHeader.value = header
  editFormData.value = {
    header_name: header.header_name || '',
    header_value: header.header_value || '',
    replace_strategy: header.replace_strategy || ReplaceStrategy.REPLACE,
    priority: header.priority || 50,
    is_active: header.is_active !== undefined ? header.is_active : true,
    ttl: header.ttl || 3600,
    scope: header.scope || null
  }
  editDialogVisible.value = true
}

// 更新Session Header
async function updateHeader() {
  if (!editFormData.value.header_name.trim() || !editFormData.value.header_value.trim()) {
    toast.add({
      severity: 'warn',
      summary: '验证失败',
      detail: '请填写Header名称和值',
      life: 3000,
    })
    return
  }

  if (!editingHeader.value?.id) {
    toast.add({
      severity: 'error',
      summary: '错误',
      detail: '无效的Header ID',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    const res = await updateSessionHeader(editingHeader.value.header_name, editFormData.value)
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '更新成功',
        detail: 'Session Header已更新',
        life: 3000,
      })
      editDialogVisible.value = false
      // 重新加载数据
      await loadSessionHeaders()
    } else {
      toast.add({
        severity: 'error',
        summary: '更新失败',
        detail: res.message || '更新失败',
        life: 3000,
      })
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '更新失败',
      detail: error.message || '更新失败',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

// 确认删除
function confirmDelete(header: any) {
  confirm.require({
    message: `确定要删除Header "${header.header_name}" 吗？`,
    header: '确认删除',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '删除',
    rejectLabel: '取消',
    accept: () => deleteHeader(header.header_name),
  })
}

// 删除Session Header
async function deleteHeader(headerName: string) {
  try {
    // 调用删除API
    const res = await deleteSessionHeader(headerName)
    if (res.success) {
      toast.add({
        severity: 'success',
        summary: '删除成功',
        detail: 'Session Header已删除',
        life: 3000,
      })
      // 重新加载数据
      await loadSessionHeaders()
    } else {
      toast.add({
        severity: 'error',
        summary: '删除失败',
        detail: res.message || '删除失败',
        life: 3000,
      })
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '删除失败',
      detail: error.message || '删除失败',
      life: 3000,
    })
  }
}

// 切换启用状态
async function toggleActive(header: any) {
  try {
    const newStatus = !header.is_active
    // 调用更新API
    const res = await updateSessionHeader(header.header_name, {
      header_value: header.header_value,
      replace_strategy: header.replace_strategy,
      priority: header.priority,
      is_active: newStatus,
      scope: header.scope
    })
    
    if (res.success) {
      // 更新本地状态
      const index = sessionHeaders.value.findIndex(h => h.id === header.id)
      if (index !== -1) {
        sessionHeaders.value[index].is_active = newStatus
      }
      toast.add({
        severity: 'success',
        summary: '状态已更新',
        detail: `已${newStatus ? '启用' : '禁用'} "${header.header_name}"`,
        life: 3000,
      })
    } else {
      toast.add({
        severity: 'error',
        summary: '操作失败',
        detail: res.message || '更新状态失败',
        life: 3000,
      })
    }
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: '操作失败',
      detail: error.message || '更新状态失败',
      life: 3000,
    })
  }
}

// 批量操作函数
function clearSelection() {
  selectedSessionHeaders.value = []
}

function confirmBatchDeleteHeaders() {
  if (selectedSessionHeaders.value.length === 0) return
  
  confirm.require({
    message: `确定要删除选中的 ${selectedSessionHeaders.value.length} 条会话Header吗？此操作不可撤销。`,
    header: '批量删除确认',
    icon: 'pi pi-exclamation-triangle',
    rejectClass: 'p-button-secondary p-button-outlined',
    rejectLabel: '取消',
    acceptLabel: '删除',
    acceptClass: 'p-button-danger',
    accept: () => {
      batchDeleteHeaders()
    },
  })
}

async function batchDeleteHeaders() {
  if (selectedSessionHeaders.value.length === 0) return
  
  let successCount = 0
  let errorCount = 0
  
  for (const header of selectedSessionHeaders.value) {
    try {
      await deleteHeader(header.header_name)
      successCount++
    } catch (error) {
      errorCount++
      console.error('删除会话Header失败:', error)
    }
  }
  
  await loadSessionHeaders()
  
  if (errorCount === 0) {
    toast.add({
      severity: 'success',
      summary: '批量删除成功',
      detail: `成功删除 ${successCount} 条会话Header`,
      life: 3000,
    })
  } else {
    toast.add({
      severity: 'warning',
      summary: '批量删除部分成功',
      detail: `成功删除 ${successCount} 条，失败 ${errorCount} 条`,
      life: 3000,
    })
  }
  
  clearSelection()
}

async function batchToggleActiveHeaders(isActive: boolean) {
  if (selectedSessionHeaders.value.length === 0) return
  
  let successCount = 0
  let errorCount = 0
  
  for (const header of selectedSessionHeaders.value) {
    try {
      // 调用updateSessionHeader来更新状态
      await updateSessionHeader(header.header_name, {
        header_name: header.header_name,
        header_value: header.header_value,
        replace_strategy: header.replace_strategy,
        priority: header.priority,
        scope: header.scope,
        is_active: isActive
      })
      successCount++
    } catch (error) {
      errorCount++
      console.error(`${isActive ? '启用' : '禁用'}会话Header失败:`, error)
    }
  }
  
  await loadSessionHeaders()
  
  const action = isActive ? '启用' : '禁用'
  
  if (errorCount === 0) {
    toast.add({
      severity: 'success',
      summary: `批量${action}成功`,
      detail: `成功${action} ${successCount} 条会话Header`,
      life: 3000,
    })
  } else {
    toast.add({
      severity: 'warning',
      summary: `批量${action}部分成功`,
      detail: `成功${action} ${successCount} 条，失败 ${errorCount} 条`,
      life: 3000,
    })
  }
  
  clearSelection()
}
</script>

<style scoped lang="scss">
.session-headers-config {
  // 搜索过滤工具栏样式
  .search-filter-card {
    :deep(.p-card-content) {
      padding: 1rem;
    }

    .search-filter-toolbar {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;

      .search-area {
        flex: 0 0 280px;
        max-width: 280px;

        :deep(.p-iconfield) {
          display: flex;
          align-items: center;
          position: relative;

          .p-inputicon {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            left: 0.75rem;
            color: var(--text-color-secondary);
          }
        }

        .search-input {
          width: 100%;
          border-radius: 8px;
          border: 2px solid var(--surface-border);
          transition: all 0.2s ease;
          padding-left: 2.5rem;

          &:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
          }
        }
      }

      .filter-area {
        display: flex;
        gap: 1rem;
        align-items: center;

        .filter-group {
          display: flex;
          align-items: center;
          gap: 0.5rem;

          .filter-label {
            font-weight: 500;
            color: var(--text-color-secondary);
            white-space: nowrap;
          }

          .filter-dropdown {
            min-width: 120px;
          }
        }
      }

      .action-area {
        display: flex;
        gap: 0.5rem;
        align-items: center;
        margin-left: auto;
        flex-wrap: wrap;
      }
    }
  }

  .session-table {
    .header-value {
      font-family: monospace;
      font-size: 0.9em;
    }

    .expire-time,
    .create-time {
      font-size: 0.9em;
      color: var(--text-color-secondary);
    }
  }

  code {
    font-family: monospace;
  }
}

// Session对话框样式优化
:deep(.session-dialog) {
  max-width: calc(100vw - 4rem);
  max-height: calc(100vh - 4rem);

  .p-dialog-header {
    padding: 1.5rem;
    border-bottom: 1px solid var(--surface-border);
  }

  .p-dialog-content {
    padding: 0;
    overflow: hidden;
  }

  .p-dialog-footer {
    padding: 1.5rem 2rem 2rem 2rem !important; // 增加底部padding，避免按钮贴边
    border-top: 1px solid var(--surface-border);
    background: var(--surface-50);
    display: flex;
    gap: 0.75rem; // 按钮之间的间距
    justify-content: flex-end; // 按钮右对齐
  }
}

// 左标签布局样式
.field-horizontal {
  @apply flex flex-col lg:flex-row lg:items-start lg:gap-4 mb-6;
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;

  .field-label-left {
    @apply lg:w-48 lg:pt-2 lg:text-right font-medium text-sm mb-2 lg:mb-0;
    min-width: 120px;
    max-width: 100%;
    flex-shrink: 0;
  }

  .field-content {
    @apply flex-1 min-w-0 max-w-full;

    // 应用统一的输入组件样式
    .p-inputtext,
    .p-inputnumber input,
    .p-dropdown,
    .p-multiselect {
      @extend .uniform-input;
    }

    .p-textarea {
      @extend .uniform-textarea;
    }

    .p-checkbox,
    .p-radiobutton {
      max-width: 100%;
      box-sizing: border-box;
    }

    .field-help {
      @apply text-xs mt-2 block;
      word-wrap: break-word;
      max-width: 100%;
    }

    // 复选框样式 - 使用更高优先级
    :deep(.p-checkbox) {
      .p-checkbox-box {
        width: 18px !important;
        height: 18px !important;
        border-radius: 4px !important;
        border: 1px solid var(--surface-border) !important;
        background: var(--surface-0) !important;
        transition: all 0.2s ease !important;
        position: relative !important;

        &.p-highlight {
          background: var(--primary-color) !important;
          border-color: var(--primary-color) !important;

          // 确保SVG图标显示
          .p-checkbox-icon {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            color: white !important;
            width: 14px !important;
            height: 14px !important;
            position: absolute !important;
            top: 50% !important;
            left: 50% !important;
            transform: translate(-50%, -50%) !important;
            z-index: 10 !important;
          }
        }
      }
    }

    // 全局强制样式
    :deep(.p-datatable .p-checkbox-box.p-highlight) {
      background: var(--primary-color) !important;
      border-color: var(--primary-color) !important;
    }

    :deep(.p-datatable .p-checkbox-box.p-highlight .p-checkbox-icon) {
      display: flex !important;
      color: white !important;
      visibility: visible !important;
      opacity: 1 !important;
    }
  }
}

// 防止长文本溢出
.text-truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

// 统一输入框样式
.uniform-input {
  width: 100% !important;
  height: 40px !important;
  border: 2px solid var(--surface-border) !important;
  border-radius: 8px !important;
  padding: 0 0.75rem !important;
  font-size: 14px !important;
  line-height: 1.5 !important;
  transition: all 0.2s ease !important;
  box-sizing: border-box !important;
  background: var(--surface-0) !important;
  color: var(--text-color) !important;

  &:hover:not(.p-disabled) {
    border-color: var(--primary-color) !important;
  }

  &:focus {
    border-color: var(--primary-color) !important;
    box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1) !important;
    outline: none !important;
  }

  &::placeholder {
    color: var(--text-color-secondary) !important;
    opacity: 0.7 !important;
  }
}

// 统一文本域样式
.uniform-textarea {
  width: 100% !important;
  min-height: 120px !important;
  border: 2px solid var(--surface-border) !important;
  border-radius: 8px !important;
  padding: 0.75rem !important;
  font-size: 14px !important;
  line-height: 1.5 !important;
  transition: all 0.2s ease !important;
  box-sizing: border-box !important;
  background: var(--surface-0) !important;
  color: var(--text-color) !important;
  resize: vertical !important;
  font-family: inherit !important;

  &:hover:not(.p-disabled) {
    border-color: var(--primary-color) !important;
  }

  &:focus {
    border-color: var(--primary-color) !important;
    box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1) !important;
    outline: none !important;
  }

  &::placeholder {
    color: var(--text-color-secondary) !important;
    opacity: 0.7 !important;
  }
}

// 统一按钮配色
.uniform-button {
  transition: all 0.2s ease !important;
  border-radius: 8px !important;
  font-weight: 500 !important;
  font-size: 14px !important;

  &:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1) !important;
  }

  &:active {
    transform: translateY(0) !important;
  }
}

// 统一卡片配色
.uniform-card {
  border-radius: 12px !important;
  border: 1px solid var(--surface-border) !important;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06) !important;
  background: var(--surface-0) !important;
  transition: all 0.3s ease !important;

  &:hover {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1) !important;
    border-color: var(--primary-200) !important;
  }

  .p-card-header {
    background: linear-gradient(135deg, var(--surface-50) 0%, var(--surface-100) 100%) !important;
    border-bottom: 1px solid var(--surface-border) !important;
    border-radius: 12px 12px 0 0 !important;
  }

  .p-card-title {
    color: var(--text-color) !important;
    font-weight: 600 !important;
    font-size: 16px !important;
    margin: 0 !important;

    i {
      color: var(--primary-color) !important;
      font-size: 18px !important;
    }
  }

  .p-card-content {
    padding: 1.5rem !important;
    color: var(--text-color) !important;
  }
}

// 统一图标配色
.uniform-icon {
  color: var(--primary-color) !important;
  font-size: 16px !important;

  &.success {
    color: var(--green-500) !important;
  }

  &.info {
    color: var(--blue-500) !important;
  }

  &.warning {
    color: var(--orange-500) !important;
  }

  &.danger {
    color: var(--red-500) !important;
  }
}

// 统一标签配色
.uniform-tag {
  border-radius: 6px !important;
  font-size: 12px !important;
  font-weight: 500 !important;
  padding: 0.25rem 0.75rem !important;

  &.success {
    background: var(--green-50) !important;
    color: var(--green-700) !important;
    border: 1px solid var(--green-200) !important;
  }

  &.info {
    background: var(--blue-50) !important;
    color: var(--blue-700) !important;
    border: 1px solid var(--blue-200) !important;
  }

  &.warning {
    background: var(--orange-50) !important;
    color: var(--orange-700) !important;
    border: 1px solid var(--orange-200) !important;
  }

  &.danger {
    background: var(--red-50) !important;
    color: var(--red-700) !important;
    border: 1px solid var(--red-200) !important;
  }
}

.text-break {
  word-wrap: break-word;
  word-break: break-word;
  max-width: 100%;
}

.dialog-content {
  padding: 2rem 2rem 3rem 2rem; // 增加底部padding，避免按钮贴边
  max-height: calc(85vh - 200px);
  overflow-y: auto;
  overflow-x: hidden;

  // 防止内容溢出的通用设置
  * {
    box-sizing: border-box;
  }

  // 自定义滚动条样式
  &::-webkit-scrollbar {
    width: 8px;
  }

  &::-webkit-scrollbar-track {
    background: var(--surface-100);
    border-radius: 4px;
  }

  &::-webkit-scrollbar-thumb {
    background: var(--surface-300);
    border-radius: 4px;

    &:hover {
      background: var(--surface-400);
    }
  }

  // 卡片通用样式
  :deep(.p-card) {
    @extend .uniform-card;
    margin-bottom: 1.5rem;

    &:last-child {
      margin-bottom: 0;
    }
  }

  // 信息卡片样式
  .info-card {
    .format-code {
      background: var(--blue-50);
      color: var(--blue-700);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
      font-size: 0.875rem;
      font-weight: 500;
      border: 1px solid var(--blue-200);
    }

    ul {
      margin: 0.5rem 0 0 0;
      padding-left: 1.5rem;

      li {
        margin-bottom: 0.5rem;
        line-height: 1.6;
        color: var(--text-color-secondary);

        &:last-child {
          margin-bottom: 0;
        }
      }
    }
  }

  // 输入区域卡片样式
  .input-card {
    .input-area {
      .headers-textarea {
        width: 100%;
        padding: 0.875rem;
        font-size: 0.9rem;
        border: 1px solid var(--surface-border);
        border-radius: 6px;
        transition: all 0.2s ease;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        line-height: 1.6;
        resize: vertical;
        min-height: 240px;
        background: var(--surface-0);

        &:enabled:hover {
          border-color: var(--primary-color);
        }

        &:enabled:focus {
          border-color: var(--primary-color);
          box-shadow: 0 0 0 2px rgba(var(--primary-color-rgb), 0.1);
          outline: none;
        }

        &::placeholder {
          color: var(--text-color-secondary);
          opacity: 0.6;
        }
      }

      .input-stats {
        margin-top: 0.75rem;
        display: flex;
        justify-content: space-between;
        align-items: center;

        small {
          font-size: 0.875rem;
          color: var(--text-color-secondary);
        }
      }
    }

    .file-upload-area {
      .file-input {
        width: 100%;
        padding: 1rem;
        border: 2px dashed var(--surface-border);
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s ease;
        background: var(--surface-0);

        &:hover {
          border-color: var(--primary-color);
          background: var(--primary-50);
        }
      }

      .file-preview {
        margin-top: 1.25rem;

        .file-preview-header {
          margin-bottom: 0.75rem;
          padding: 0.75rem 1rem;
          background: var(--surface-50);
          border-radius: 6px;
          border-left: 3px solid var(--primary-color);

          .font-semibold {
            font-weight: 600;
            color: var(--text-color);
          }
        }
      }
    }
  }

  // 配置卡片样式
  .config-card {
    .field {
      margin-bottom: 1.5rem;

      &:last-child {
        margin-bottom: 0;
      }
    }

    // 浮动标签优化
    :deep(.p-float-label) {
      label {
        font-weight: 500;
        font-size: 0.95rem;
        color: var(--text-color-secondary);
        left: 0.75rem;
        transition: all 0.2s ease;

        i {
          color: var(--primary-color);
          margin-right: 0.25rem;
        }
      }

      input:focus ~ label,
      input.p-filled ~ label,
      .p-inputwrapper-focus ~ label,
      .p-inputwrapper-filled ~ label {
        top: -0.75rem;
        font-size: 0.875rem;
        background: var(--surface-0);
        padding: 0 0.25rem;
      }
    }

    // 输入数字组件样式
    :deep(.p-inputnumber) {
      width: 100%;

      .p-inputnumber-input {
        width: 100%;
        padding: 0.75rem;
        font-size: 0.95rem;
        border: 1px solid var(--surface-border);
        border-radius: 6px;
        transition: all 0.2s ease;
        background: var(--surface-0);

        &:enabled:hover {
          border-color: var(--primary-color);
        }

        &:enabled:focus {
          border-color: var(--primary-color);
          box-shadow: 0 0 0 2px rgba(var(--primary-color-rgb), 0.1);
          outline: none;
        }
      }
    }

    small {
      display: block;
      margin-top: 0.5rem;
      font-size: 0.875rem;
      color: var(--text-color-secondary);
      line-height: 1.4;
    }
  }

  // 消息组件样式
  :deep(.p-message) {
    border-radius: 8px;
    border: none;
    margin: 0;

    .p-message-wrapper {
      border-radius: 8px;
      padding: 0.875rem 1rem;
    }

    .p-message-icon {
      font-size: 1.25rem;
    }

    &.p-message-info .p-message-wrapper {
      background: var(--blue-50);
      color: var(--blue-900);
      border-left: 3px solid var(--blue-500);
    }
  }
}
</style>
