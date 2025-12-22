# API服务封装

<cite>
**本文档引用的文件**
- [index.ts](file://src/frontEnd/src/api/index.ts)
- [task.ts](file://src/frontEnd/src/api/task.ts)
- [scanPreset.ts](file://src/frontEnd/src/api/scanPreset.ts)
- [headerRule.ts](file://src/frontEnd/src/api/headerRule.ts)
- [auth.ts](file://src/frontEnd/src/api/auth.ts)
- [request.ts](file://src/frontEnd/src/api/request.ts)
- [api.ts](file://src/frontEnd/src/types/api.ts)
- [task.ts](file://src/frontEnd/src/types/task.ts)
- [scanPreset.ts](file://src/frontEnd/src/types/scanPreset.ts)
- [headerRule.ts](file://src/frontEnd/src/types/headerRule.ts)
- [auth.ts](file://src/frontEnd/src/stores/auth.ts)
- [task.ts](file://src/frontEnd/src/stores/task.ts)
- [scanPreset.ts](file://src/frontEnd/src/stores/scanPreset.ts)
</cite>

## 目录
1. [项目结构](#项目结构)
2. [API模块化组织](#apimodularization)
3. [类型安全设计](#type-safety)
4. [HTTP方法封装](#http-methods)
5. [API与状态管理集成](#api-state-integration)
6. [错误处理契约](#error-handling)
7. [API版本管理](#api-versioning)

## 项目结构

前端API服务位于`src/frontEnd/src/api`目录下，采用模块化设计，每个功能模块都有独立的API文件。核心API模块包括任务管理、扫描预设、请求头规则和认证服务。API请求的底层封装通过`request.ts`文件实现，使用Axios进行HTTP通信，并配置了请求/响应拦截器。类型定义位于`types`目录下，确保前端各模块的类型安全。

```mermaid
graph TB
subgraph "API模块"
A[auth.ts]
B[task.ts]
C[scanPreset.ts]
D[headerRule.ts]
E[index.ts]
end
subgraph "核心依赖"
F[request.ts]
G[api.ts]
end
subgraph "类型定义"
H[task.ts]
I[scanPreset.ts]
J[headerRule.ts]
K[common.ts]
end
subgraph "状态管理"
L[auth.ts]
M[task.ts]
N[scanPreset.ts]
end
F --> A
F --> B
F --> C
F --> D
G --> F
H --> B
I --> C
J --> D
K --> A
A --> L
B --> M
C --> N
E --> A
E --> B
E --> C
E --> D
```

**Diagram sources**
- [index.ts](file://src/frontEnd/src/api/index.ts)
- [task.ts](file://src/frontEnd/src/api/task.ts)
- [scanPreset.ts](file://src/frontEnd/src/api/scanPreset.ts)
- [headerRule.ts](file://src/frontEnd/src/api/headerRule.ts)
- [request.ts](file://src/frontEnd/src/api/request.ts)
- [api.ts](file://src/frontEnd/src/types/api.ts)
- [task.ts](file://src/frontEnd/src/types/task.ts)
- [scanPreset.ts](file://src/frontEnd/src/types/scanPreset.ts)
- [headerRule.ts](file://src/frontEnd/src/types/headerRule.ts)
- [auth.ts](file://src/frontEnd/src/stores/auth.ts)
- [task.ts](file://src/frontEnd/src/stores/task.ts)
- [scanPreset.ts](file://src/frontEnd/src/stores/scanPreset.ts)

## API模块化组织

API服务采用模块化组织方式，每个功能模块独立封装，通过`index.ts`文件统一导出，实现清晰的模块边界和依赖管理。

```mermaid
classDiagram
class ApiService {
<<abstract>>
+request : AxiosInstance
}
class AuthApi {
+login(data : LoginRequest) : Promise~LoginResponse~
+refreshToken() : Promise~{token : string}~
+getVersion() : Promise~{version : string}~
+checkAuthRequired() : Promise~{required : boolean}~
}
class TaskApi {
+getTaskList() : Promise~Task[]~
+addTask(taskData : Partial~Task~) : Promise~{engineid : number; taskid : string}~
+deleteTask(taskId : string) : Promise~void~
+stopTask(taskId : string) : Promise~void~
+findTaskByUrl(urlPath : string) : Promise~Task[]~
+getTaskLogs(taskId : string) : Promise~string[]~
+batchDeleteTasks(taskIds : string[]) : Promise~void~
+batchStopTasks(taskIds : string[]) : Promise~void~
+flushTasks() : Promise~void~
+getScanOptions(taskId : string) : Promise~any~
+getHttpRequestInfo(taskId : string) : Promise~any~
+getPayloadDetail(taskId : string) : Promise~PayloadEntry[]~
}
class ScanPresetApi {
+getAllPresets(includeInactive : boolean) : Promise~ScanPresetListResponse~
+getConfigOptions() : Promise~ConfigOptionsResponse~
+getDefaultPreset() : Promise~ScanPreset | null~
+updateDefaultPreset(options : ScanOptions) : Promise~ScanPreset | null~
+getPresetConfigs() : Promise~ScanPreset[]~
+getHistoryConfigs(limit : number) : Promise~ScanPreset[]~
+getPresetById(presetId : number) : Promise~ScanPreset | null~
+createPreset(data : ScanPresetCreate) : Promise~ScanPreset | null~
+updatePreset(presetId : number, data : ScanPresetUpdate) : Promise~ScanPreset | null~
+deletePreset(presetId : number) : Promise~boolean~
+addToHistory(name : string, options : ScanOptions) : Promise~ScanPreset | null~
+applyPreset(presetId : number, baseOptions? : ScanOptions) : Promise~ScanOptions~
}
class HeaderRuleApi {
+getPersistentRules(activeOnly : boolean) : Promise~any~
+getPersistentRuleById(ruleId : number) : Promise~any~
+createPersistentRule(rule : PersistentHeaderRuleCreate) : Promise~any~
+updatePersistentRule(ruleId : number, rule : PersistentHeaderRuleUpdate) : Promise~any~
+deletePersistentRule(ruleId : number) : Promise~any~
+setSessionHeaders(headers : SessionHeaderBatchCreate) : Promise~any~
+getSessionHeaders() : Promise~any~
+deleteSessionHeader(headerName : string) : Promise~any~
+updateSessionHeader(headerName : string, header : Partial~any~) : Promise~any~
+clearSessionHeaders() : Promise~any~
+previewHeaderProcessing(previewData : HeaderPreviewRequest) : Promise~any~
+getHeaderManagementStats() : Promise~any~
}
ApiService <|-- AuthApi
ApiService <|-- TaskApi
ApiService <|-- ScanPresetApi
ApiService <|-- HeaderRuleApi
```

**Diagram sources**
- [auth.ts](file://src/frontEnd/src/api/auth.ts)
- [task.ts](file://src/frontEnd/src/api/task.ts)
- [scanPreset.ts](file://src/frontEnd/src/api/scanPreset.ts)
- [headerRule.ts](file://src/frontEnd/src/api/headerRule.ts)

### 统一导出机制

API模块通过`index.ts`文件实现统一导出，简化了导入路径，提高了代码的可维护性。

```typescript
/**
 * API统一导出
 */
export * from './auth'
export * from './task'
export * from './headerRule'
export { request } from './request'
```

这种设计模式使得其他模块可以统一从`@/api`路径导入所需的服务，而不需要关心具体的文件位置。

**Section sources**
- [index.ts](file://src/frontEnd/src/api/index.ts)

### 依赖注入模式

API服务与Pinia状态管理Store之间形成了依赖注入模式，API方法被注入到各个Store中，由Store负责调用和状态管理。

```mermaid
sequenceDiagram
participant Component as "组件"
participant Store as "Pinia Store"
participant API as "API服务"
participant Request as "请求封装"
participant Backend as "后端服务"
Component->>Store : 调用动作方法
Store->>API : 调用API方法
API->>Request : 发起HTTP请求
Request->>Backend : 发送请求
Backend-->>Request : 返回响应
Request-->>API : 处理响应
API-->>Store : 返回数据
Store->>Store : 更新状态
Store-->>Component : 返回结果
```

**Diagram sources**
- [task.ts](file://src/frontEnd/src/stores/task.ts)
- [task.ts](file://src/frontEnd/src/api/task.ts)
- [request.ts](file://src/frontEnd/src/api/request.ts)

## 类型安全设计

项目通过TypeScript接口定义确保了API服务的类型安全，从前端到后端的数据交互都有明确的类型约束。

### 任务模块类型定义

任务模块定义了完整的类型体系，包括任务状态枚举、任务接口、筛选条件、统计数据等。

```mermaid
classDiagram
class TaskStatus {
<<enumeration>>
PENDING = 0
RUNNING = 1
SUCCESS = 2
FAILED = 3
STOPPED = 4
TERMINATED = 5
}
class Task {
+engineid : number
+taskid : string
+scanUrl : string
+host : string
+status : TaskStatus
+createTime : string
+startTime? : string
+headers? : string[]
+body? : string
+options? : TaskOptions
+updateTime? : string
+remote_addr? : string
+injected? : boolean
+errors? : number
+logs? : number
}
class TaskOptions {
+level? : number
+risk? : number
+technique? : string
+dbms? : string
+threads? : number
}
class TaskFilters {
+urlKeyword? : string
+messageKeyword? : string
+status? : TaskStatus
+startDate? : string
+endDate? : string
+execStartDate? : string
+execEndDate? : string
+injectableStatus? : 'injectable' | 'not_injectable' | 'unknown'
}
class TaskStats {
+total : number
+running : number
+pending : number
+success : number
+failed : number
+stopped : number
+terminated : number
+injectable : number
+nonInjectable : number
+unknown : number
}
TaskStatus --> Task : "使用"
Task --> TaskOptions : "包含"
Task --> TaskFilters : "用于筛选"
Task --> TaskStats : "用于统计"
```

**Diagram sources**
- [task.ts](file://src/frontEnd/src/types/task.ts)

### 扫描预设类型定义

扫描预设模块定义了丰富的类型，包括扫描选项、预设配置、创建/更新请求等。

```mermaid
classDiagram
class PresetType {
<<enumeration>>
default
preset
history
}
class ScanOptions {
+level? : number
+risk? : number
+string? : string
+notString? : string
+regexp? : string
+code? : number
+smart? : boolean
+textOnly? : boolean
+titles? : boolean
+testParameter? : string
+skip? : string
+skipStatic? : boolean
+paramExclude? : string
+dbms? : string
+os? : string
+prefix? : string
+suffix? : string
+tamper? : string
+technique? : string
+timeSec? : number
+timeout? : number
+retries? : number
+delay? : number
+randomAgent? : boolean
+proxy? : string
+tor? : boolean
+optimize? : boolean
+predictOutput? : boolean
+keepAlive? : boolean
+nullConnection? : boolean
+threads? : number
+getBanner? : boolean
+getCurrentUser? : boolean
+getCurrentDb? : boolean
+getHostname? : boolean
+isDba? : boolean
+getUsers? : boolean
+getPasswordHashes? : boolean
+getPrivileges? : boolean
+getRoles? : boolean
+getDbs? : boolean
+getTables? : boolean
+getColumns? : boolean
+dumpTable? : boolean
+dumpAll? : boolean
+db? : string
+tbl? : string
+col? : string
+batch? : boolean
+forms? : boolean
+crawlDepth? : number
+flushSession? : boolean
+freshQueries? : boolean
+verbose? : number
}
class ScanPreset {
+id? : number
+name : string
+description? : string
+preset_type : PresetType
+options : ScanOptions
+parameter_string? : string
+is_active : boolean
+created_at? : string
+updated_at? : string
+last_used_at? : string
+use_count : number
}
class ScanPresetCreate {
+name : string
+description? : string
+preset_type? : PresetType
+options? : ScanOptions
+parameter_string? : string
}
class ScanPresetUpdate {
+name? : string
+description? : string
+options? : ScanOptions
+parameter_string? : string
+is_active? : boolean
}
class ScanPresetListResponse {
+presets : ScanPreset[]
+total : number
+default_preset? : ScanPreset
}
class ConfigOptionsResponse {
+default : ScanPreset | null
+presets : ScanPreset[]
+history : ScanPreset[]
}
PresetType --> ScanPreset : "使用"
ScanOptions --> ScanPreset : "包含"
ScanPreset --> ScanPresetCreate : "创建"
ScanPreset --> ScanPresetUpdate : "更新"
ScanPreset --> ScanPresetListResponse : "包含"
ScanPreset --> ConfigOptionsResponse : "包含"
```

**Diagram sources**
- [scanPreset.ts](file://src/frontEnd/src/types/scanPreset.ts)

### 请求头规则类型定义

请求头规则模块定义了作用域配置、替换策略枚举、持久化规则等类型。

```mermaid
classDiagram
class HeaderScope {
+protocol_pattern? : string
+host_pattern? : string
+ip_pattern? : string
+port_pattern? : string
+path_pattern? : string
+use_regex? : boolean
}
class ReplaceStrategy {
<<enumeration>>
REPLACE = 'REPLACE'
APPEND = 'APPEND'
PREPEND = 'PREPEND'
CONDITIONAL = 'CONDITIONAL'
UPSERT = 'UPSERT'
}
class PersistentHeaderRule {
+id : number
+name : string
+header_name : string
+header_value : string
+replace_strategy : ReplaceStrategy
+match_condition? : string
+priority : number
+is_active : boolean
+scope? : HeaderScope | null
+created_at? : string
+updated_at? : string
}
class PersistentHeaderRuleCreate {
+name : string
+header_name : string
+header_value : string
+replace_strategy? : ReplaceStrategy
+match_condition? : string
+priority? : number
+is_active? : boolean
+scope? : HeaderScope | null
}
class PersistentHeaderRuleUpdate {
+name? : string
+header_name? : string
+header_value? : string
+replace_strategy? : ReplaceStrategy
+match_condition? : string
+priority? : number
+is_active? : boolean
+scope? : HeaderScope | null
}
class SessionHeader {
+id? : number
+header_name : string
+header_value : string
+replace_strategy? : ReplaceStrategy
+priority? : number
+is_active? : boolean
+ttl? : number
+scope? : HeaderScope | null
+created_at? : string
+updated_at? : string
}
class SessionHeaderBatchCreate {
+headers : SessionHeader[]
}
class HeaderPreviewRequest {
+headers : string[]
+target_url? : string
}
HeaderScope --> PersistentHeaderRule : "包含"
ReplaceStrategy --> PersistentHeaderRule : "使用"
HeaderScope --> SessionHeader : "包含"
ReplaceStrategy --> SessionHeader : "使用"
SessionHeader --> SessionHeaderBatchCreate : "包含"
PersistentHeaderRule --> PersistentHeaderRuleCreate : "创建"
PersistentHeaderRule --> PersistentHeaderRuleUpdate : "更新"
```

**Diagram sources**
- [headerRule.ts](file://src/frontEnd/src/types/headerRule.ts)

### 基础响应类型

定义了统一的API响应基础结构，确保所有API响应都有统一的格式。

```mermaid
classDiagram
class BaseResponse~T~ {
+code : number
+success : boolean
+message : string
+data : T
}
class ListResponse~T~ {
+code : number
+success : boolean
+message : string
+data : T[]
}
class ItemResponse~T~ {
+code : number
+success : boolean
+message : string
+data : T
}
class PaginationParams {
+page : number
+pageSize : number
}
class PaginatedData~T~ {
+items : T[]
+total : number
+page : number
+pageSize : number
}
BaseResponse~T~ <|-- ListResponse~T~
BaseResponse~T~ <|-- ItemResponse~T~
PaginatedData~T~ --> PaginationParams : "包含"
```

**Diagram sources**
- [api.ts](file://src/frontEnd/src/types/api.ts)

## HTTP方法封装

API服务对HTTP方法进行了封装，提供了简洁的调用接口，同时处理了请求参数和响应数据的转换。

### 请求方法封装

`request.ts`文件封装了Axios实例，提供了GET、POST、PUT、PATCH、DELETE等HTTP方法的封装。

```mermaid
classDiagram
class RequestService {
-instance : AxiosInstance
+get~T~(url : string, config? : AxiosRequestConfig) : Promise~T~
+post~T~(url : string, data? : any, config? : AxiosRequestConfig) : Promise~T~
+put~T~(url : string, data? : any, config? : AxiosRequestConfig) : Promise~T~
+patch~T~(url : string, data? : any, config? : AxiosRequestConfig) : Promise~T~
+delete~T~(url : string, config? : AxiosRequestConfig) : Promise~T~
}
class AxiosInstance {
+get(url, config)
+post(url, data, config)
+put(url, data, config)
+patch(url, data, config)
+delete(url, config)
}
RequestService --> AxiosInstance : "使用"
```

**Diagram sources**
- [request.ts](file://src/frontEnd/src/api/request.ts)

### 认证相关API

认证模块封装了用户登录、刷新令牌、获取系统版本等API方法。

```mermaid
classDiagram
class AuthApi {
+login(data : LoginRequest) : Promise~LoginResponse~
+refreshToken() : Promise~{token : string}~
+getVersion() : Promise~{version : string}~
+checkAuthRequired() : Promise~{required : boolean}~
}
class LoginRequest {
+username : string
+password : string
}
class LoginResponse {
+token : string
+userInfo : UserInfo
}
AuthApi --> LoginRequest : "使用"
AuthApi --> LoginResponse : "返回"
```

**Diagram sources**
- [auth.ts](file://src/frontEnd/src/api/auth.ts)

### 任务相关API

任务模块封装了任务的增删改查、批量操作、获取日志等API方法。

```mermaid
classDiagram
class TaskApi {
+getTaskList() : Promise~Task[]~
+addTask(taskData : Partial~Task~) : Promise~{engineid : number; taskid : string}~
+deleteTask(taskId : string) : Promise~void~
+stopTask(taskId : string) : Promise~void~
+findTaskByUrl(urlPath : string) : Promise~Task[]~
+getTaskLogs(taskId : string) : Promise~string[]~
+batchDeleteTasks(taskIds : string[]) : Promise~void~
+batchStopTasks(taskIds : string[]) : Promise~void~
+flushTasks() : Promise~void~
+getScanOptions(taskId : string) : Promise~any~
+getHttpRequestInfo(taskId : string) : Promise~any~
+getPayloadDetail(taskId : string) : Promise~PayloadEntry[]~
}
TaskApi --> Task : "使用"
TaskApi --> PayloadEntry : "返回"
```

**Diagram sources**
- [task.ts](file://src/frontEnd/src/api/task.ts)

### 扫描预设相关API

扫描预设模块封装了预设配置的增删改查、获取配置选项、应用预设等API方法。

```mermaid
classDiagram
class ScanPresetApi {
+getAllPresets(includeInactive : boolean) : Promise~ScanPresetListResponse~
+getConfigOptions() : Promise~ConfigOptionsResponse~
+getDefaultPreset() : Promise~ScanPreset | null~
+updateDefaultPreset(options : ScanOptions) : Promise~ScanPreset | null~
+getPresetConfigs() : Promise~ScanPreset[]~
+getHistoryConfigs(limit : number) : Promise~ScanPreset[]~
+getPresetById(presetId : number) : Promise~ScanPreset | null~
+createPreset(data : ScanPresetCreate) : Promise~ScanPreset | null~
+updatePreset(presetId : number, data : ScanPresetUpdate) : Promise~ScanPreset | null~
+deletePreset(presetId : number) : Promise~boolean~
+addToHistory(name : string, options : ScanOptions) : Promise~ScanPreset | null~
+applyPreset(presetId : number, baseOptions? : ScanOptions) : Promise~ScanOptions~
}
ScanPresetApi --> ScanPreset : "使用"
ScanPresetApi --> ScanPresetListResponse : "返回"
ScanPresetApi --> ConfigOptionsResponse : "返回"
ScanPresetApi --> ScanOptions : "使用"
```

**Diagram sources**
- [scanPreset.ts](file://src/frontEnd/src/api/scanPreset.ts)

### 请求头规则相关API

请求头规则模块封装了持久化规则和会话性请求头的增删改查、预览处理等API方法。

```mermaid
classDiagram
class HeaderRuleApi {
+getPersistentRules(activeOnly : boolean) : Promise~any~
+getPersistentRuleById(ruleId : number) : Promise~any~
+createPersistentRule(rule : PersistentHeaderRuleCreate) : Promise~any~
+updatePersistentRule(ruleId : number, rule : PersistentHeaderRuleUpdate) : Promise~any~
+deletePersistentRule(ruleId : number) : Promise~any~
+setSessionHeaders(headers : SessionHeaderBatchCreate) : Promise~any~
+getSessionHeaders() : Promise~any~
+deleteSessionHeader(headerName : string) : Promise~any~
+updateSessionHeader(headerName : string, header : Partial~any~) : Promise~any~
+clearSessionHeaders() : Promise~any~
+previewHeaderProcessing(previewData : HeaderPreviewRequest) : Promise~any~
+getHeaderManagementStats() : Promise~any~
}
HeaderRuleApi --> PersistentHeaderRule : "使用"
HeaderRuleApi --> SessionHeader : "使用"
HeaderRuleApi --> HeaderPreviewRequest : "使用"
```

**Diagram sources**
- [headerRule.ts](file://src/frontEnd/src/api/headerRule.ts)

## API与状态管理集成

API服务与Pinia状态管理Store紧密集成，实现了数据流的单向流动和状态的集中管理。

### 认证状态管理

认证Store管理用户认证状态，包括Token、用户信息、访问模式等，并提供登录、登出等操作。

```mermaid
classDiagram
class AuthStore {
+token : Ref~string | null~
+userInfo : Ref~UserInfo | null~
+isLocalMode : Ref~boolean~
+authRequired : Ref~boolean~
+backendHealthy : Ref~boolean~
+lastHealthCheck : Ref~number~
+isLoggedIn : ComputedRef~boolean~
+userName : ComputedRef~string~
+needAuth : ComputedRef~boolean~
+login(data : LoginRequest) : Promise~void~
+logout() : void
+checkAuth() : boolean
+initAuth() : void
+checkBackendHealth() : Promise~boolean~
+resetHealthCheck() : void
}
AuthStore --> auth : "使用"
AuthStore --> storage : "使用"
```

**Diagram sources**
- [auth.ts](file://src/frontEnd/src/stores/auth.ts)

### 任务状态管理

任务Store管理任务列表、当前任务、筛选条件、排序配置等状态，并提供获取任务列表、创建任务、删除任务等操作。

```mermaid
classDiagram
class TaskStore {
+taskList : Ref~Task[]~
+currentTask : Ref~Task | null~
+currentTaskDetail : Ref~TaskDetail | null~
+loading : Ref~boolean~
+filters : Ref~TaskFilters~
+sortConfig : Ref~SortConfig~
+selectedTaskIds : Ref~string[]~
+taskStats : ComputedRef~TaskStats~
+filteredTaskList : ComputedRef~Task[]
+sortedTaskList : ComputedRef~Task[]
+fetchTaskList() : Promise~void~
+createTask(taskData : Partial~Task~) : Promise~Task~
+deleteTask(taskId : string) : Promise~void~
+stopTask(taskId : string) : Promise~void~
+updateTaskStatus(taskId : string, status : number) : void
+setCurrentTask(task : Task | null) : void
+setFilters(newFilters : TaskFilters) : void
+clearFilters() : void
+setSortConfig(config : SortConfig) : void
+setSelectedTaskIds(ids : string[]) : void
+toggleTaskSelection(taskId : string) : void
+clearSelection() : void
+batchDeleteTasks(taskIds : string[]) : Promise~void~
+batchStopTasks(taskIds : string[]) : Promise~void~
+deleteAllTasks() : Promise~void~
}
TaskStore --> task : "使用"
```

**Diagram sources**
- [task.ts](file://src/frontEnd/src/stores/task.ts)

### 扫描预设状态管理

扫描预设Store管理预设配置列表、当前选项、选中的预设ID等状态，并提供加载配置、选择预设、更新选项等操作。

```mermaid
classDiagram
class ScanPresetStore {
+loading : Ref~boolean~
+defaultPreset : Ref~ScanPreset | null~
+presetConfigs : Ref~ScanPreset[]~
+historyConfigs : Ref~ScanPreset[]~
+allPresets : Ref~ScanPreset[]~
+currentOptions : Ref~ScanOptions~
+selectedPresetId : Ref~number | null~
+presetOptions : ComputedRef~PresetOption[]~
+loadConfigOptions() : Promise~void~
+loadAllPresets(includeInactive : boolean) : Promise~void~
+selectPreset(presetId : number) : Promise~void~
+updateOptions(options : Partial~ScanOptions~) : void
+resetOptions() : void
+updateDefaultPreset(options : ScanOptions) : Promise~ScanPreset | null~
+createPreset(data : ScanPresetCreate) : Promise~ScanPreset | null~
+updatePreset(presetId : number, data : ScanPresetUpdate) : Promise~ScanPreset | null~
+deletePreset(presetId : number) : Promise~boolean~
+saveCurrentAsPreset(name : string, description? : string) : Promise~ScanPreset | null~
+addToHistory(name : string) : Promise~ScanPreset | null~
+getEffectiveOptions() : ScanOptions
}
ScanPresetStore --> scanPreset : "使用"
```

**Diagram sources**
- [scanPreset.ts](file://src/frontEnd/src/stores/scanPreset.ts)

## 错误处理契约

API服务通过请求拦截器和响应拦截器实现了统一的错误处理契约，确保错误信息能够被正确处理和展示。

### 请求拦截器

请求拦截器在发送请求前添加认证Token和通用请求头。

```mermaid
flowchart TD
Start([开始]) --> CheckLocal["检查是否为本地访问"]
CheckLocal --> |是| SkipAuth["跳过认证"]
CheckLocal --> |否| GetToken["获取Token"]
GetToken --> CheckToken["检查Token是否存在"]
CheckToken --> |存在| AddAuth["添加Authorization头"]
CheckToken --> |不存在| SkipAuth
AddAuth --> AddCommon["添加通用请求头"]
SkipAuth --> AddCommon
AddCommon --> End([结束])
```

**Diagram sources**
- [request.ts](file://src/frontEnd/src/api/request.ts#L94-L119)

### 响应拦截器

响应拦截器处理响应数据和错误，实现重试机制和错误提示。

```mermaid
flowchart TD
Start([开始]) --> CheckSuccess["检查业务状态码"]
CheckSuccess --> |成功| ReturnData["返回data字段"]
CheckSuccess --> |失败| ShowWarning["显示警告提示"]
ShowWarning --> RejectError["拒绝Promise"]
Start --> CheckError["检查HTTP错误"]
CheckError --> |是| HandleHTTP["处理HTTP错误"]
HandleHTTP --> CheckStatus["检查状态码"]
CheckStatus --> |401| Handle401["处理401错误"]
CheckStatus --> |其他| ShowError["显示错误提示"]
Handle401 --> CheckLocal["检查是否为本地模式"]
CheckLocal --> |是| Ignore401["忽略401错误"]
CheckLocal --> |否| ClearAuth["清除认证信息"]
ClearAuth --> ShowError
Start --> CheckNetwork["检查网络错误"]
CheckNetwork --> |超时| ShowTimeout["显示超时提示"]
CheckNetwork --> |连接错误| ShowConnectError["显示连接错误提示"]
CheckNetwork --> |其他| ShowNetworkError["显示网络错误提示"]
ReturnData --> End([结束])
RejectError --> End
ShowError --> End
Ignore401 --> End
ShowTimeout --> End
ShowConnectError --> End
ShowNetworkError --> End
```

**Diagram sources**
- [request.ts](file://src/frontEnd/src/api/request.ts#L120-L204)

### 重试机制

API服务实现了智能重试机制，针对特定的HTTP状态码和网络错误进行重试。

```mermaid
flowchart TD
Start([开始]) --> CheckRetry["检查是否应该重试"]
CheckRetry --> |否| ReturnError["返回错误"]
CheckRetry --> |是| IncrementRetry["重试计数+1"]
IncrementRetry --> CheckMax["检查是否超过最大重试次数"]
CheckMax --> |是| ReturnError
CheckMax --> |否| CheckMethod["检查是否为GET请求"]
CheckMethod --> |否| ReturnError
CheckMethod --> |是| CheckResponse["检查是否有响应"]
CheckResponse --> |无响应| Wait["等待后重试"]
CheckResponse --> |有响应| CheckStatus["检查状态码"]
CheckStatus --> |可重试| Wait["等待后重试"]
CheckStatus --> |不可重试| ReturnError
Wait --> CalculateDelay["计算重试延迟"]
CalculateDelay --> WaitTime["等待指定时间"]
WaitTime --> Retry["重试请求"]
Retry --> Start
ReturnError --> End([结束])
```

**Diagram sources**
- [request.ts](file://src/frontEnd/src/api/request.ts#L66-L92)

## API版本管理

项目通过环境变量和配置文件实现了API版本管理，确保向前兼容性。

### 环境变量配置

API基础URL通过环境变量配置，支持不同环境的部署。

```typescript
// 创建axios实例
const instance: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})
```

这种设计使得API服务可以在不同环境中使用不同的基础URL，而不需要修改代码。

**Section sources**
- [request.ts](file://src/frontEnd/src/api/request.ts#L48-L55)

### 向后兼容性处理

API服务通过字段映射和数据转换确保了向前兼容性，能够处理后端可能返回的不同格式的数据。

```mermaid
flowchart TD
Start([开始]) --> ReceiveData["接收后端数据"]
ReceiveData --> CheckFormat["检查数据格式"]
CheckFormat --> |旧格式| Transform["转换为新格式"]
CheckFormat --> |新格式| UseDirectly["直接使用"]
Transform --> UseDirectly
UseDirectly --> End([结束])
```

例如，在任务模块中，后端可能返回字符串或数字状态，前端通过`mapBackendStatus`函数将其映射为统一的枚举值：

```typescript
function mapBackendStatus(status: string | number): TaskStatus {
  // 如果已经是数字，直接返回
  if (typeof status === 'number') {
    return status as TaskStatus
  }
  
  // 字符串状态映射
  const statusMap: Record<string, TaskStatus> = {
    'New': TaskStatus.PENDING,
    'Pending': TaskStatus.PENDING,
    'Running': TaskStatus.RUNNING,
    'Runnable': TaskStatus.RUNNING,
    'Blocked': TaskStatus.RUNNING,
    'Terminated': TaskStatus.TERMINATED,
    'Success': TaskStatus.SUCCESS,
    'Completed': TaskStatus.SUCCESS,
    'Failed': TaskStatus.FAILED,
    'Error': TaskStatus.FAILED,
    'Stopped': TaskStatus.STOPPED,
  }
  
  // 大小写不敏感匹配
  const normalizedStatus = Object.keys(statusMap).find(
    key => key.toLowerCase() === status.toLowerCase()
  )
  
  if (normalizedStatus && statusMap[normalizedStatus] !== undefined) {
    return statusMap[normalizedStatus] as TaskStatus
  }
  
  // 默认返回 PENDING
  console.warn(`Unknown task status: ${status}, defaulting to PENDING`)
  return TaskStatus.PENDING
}
```

**Section sources**
- [task.ts](file://src/frontEnd/src/api/task.ts#L68-L101)