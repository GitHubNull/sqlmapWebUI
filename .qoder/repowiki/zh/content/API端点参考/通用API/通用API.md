# 通用API

<cite>
**本文档引用的文件**
- [app.py](file://src/backEnd/app.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py)
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [Task.py](file://src/backEnd/model/Task.py)
- [header_processor.py](file://src/backEnd/utils/header_processor.py)
- [auth.py](file://src/backEnd/utils/auth.py)
</cite>

## 更新摘要
**已更改内容**
- 在“简介”部分添加了健康检查端点的描述
- 在“项目结构”中更新了Mermaid图示以包含新的健康检查路由
- 新增了“健康检查端点”专门章节
- 更新了“架构概述”中的系统架构图
- 在“故障排除指南”中添加了健康检查相关的故障排除信息

**新增部分**
- 健康检查端点详细说明
- 健康检查API使用示例

**已弃用/移除部分**
- 无

**源码追踪系统更新**
- 添加了app.py中health_check函数的源码引用
- 更新了架构图的源码引用信息

## 目录
1. [简介](#简介)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [架构概述](#架构概述)
5. [详细组件分析](#详细组件分析)
6. [依赖分析](#依赖分析)
7. [性能考虑](#性能考虑)
8. [健康检查端点](#健康检查端点)
9. [故障排除指南](#故障排除指南)
10. [结论](#结论)

## 简介
本文档详细描述了基于FastAPI构建的通用API，重点介绍任务管理和请求头规则管理功能。API提供RESTful端点用于创建、启动、停止、删除和查询任务，同时支持持久化规则和会话级别规则的CRUD操作。系统集成了sqlmap安全测试工具，通过API接口实现自动化漏洞扫描功能。所有端点均要求Bearer Token认证，确保接口访问的安全性。新增了`/api/health`健康检查端点，用于前端监控后端服务的可用性和运行状态。

## 项目结构
该项目采用分层架构设计，包含API路由、业务服务、数据模型和工具模块。核心功能分布在`service`目录下的`taskService.py`和`headerRuleService.py`文件中，分别处理任务管理和请求头规则管理。API端点通过`api/chromeExApi/admin.py`文件定义，使用FastAPI框架实现RESTful接口。数据模型定义在`model`目录中，包括任务、请求头规则等核心实体。

```mermaid
graph TD
A[app.py] --> B[admin.py]
B --> C[taskService.py]
B --> D[headerRuleService.py]
C --> E[Task.py]
D --> F[header_processor.py]
G[auth.py] --> B
A --> H[health_check]
```

**图示来源**
- [app.py](file://src/backEnd/app.py#L1-L44)
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py#L1-L117)

## 核心组件
系统核心组件包括任务服务和请求头规则服务。任务服务负责管理sqlmap扫描任务的全生命周期，包括任务创建、启动、停止和状态查询。请求头规则服务提供持久化规则和会话级别规则的管理功能，支持规则的批量导入和预览处理效果。两个服务通过DataStore共享数据状态，确保多线程环境下的数据一致性。

**组件来源**
- [taskService.py](file://src/backEnd/service/taskService.py#L1-L531)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L1-L799)

## 架构概述
系统采用微服务架构模式，前端通过Vue框架构建用户界面，后端使用FastAPI提供RESTful API。API层负责请求路由和认证，服务层实现业务逻辑，数据层管理任务状态和规则存储。请求头处理流程在任务创建时自动触发，依次应用持久化规则和会话级别规则，确保每次扫描都使用最新的请求头配置。

```mermaid
graph TB
subgraph "前端"
UI[Vue用户界面]
end
subgraph "API层"
API[FastAPI服务器]
Auth[认证中间件]
HealthCheck[健康检查端点]
end
subgraph "服务层"
TaskService[任务服务]
HeaderService[请求头规则服务]
end
subgraph "数据层"
DataStore[内存数据存储]
DB[(SQLite数据库)]
end
UI --> API
API --> Auth
API --> HealthCheck
Auth --> TaskService
Auth --> HeaderService
TaskService --> DataStore
HeaderService --> DataStore
DataStore --> DB
```

**图示来源**
- [app.py](file://src/backEnd/app.py#L1-L44)
- [taskService.py](file://src/backEnd/service/taskService.py#L1-L531)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L1-L799)

## 详细组件分析
### 任务管理组件分析
任务管理组件提供完整的任务生命周期管理功能，包括创建、启动、停止、删除和查询操作。每个任务对应一个唯一的task_id，用于标识和管理特定的sqlmap扫描会话。任务状态机包含新建、可运行、运行中、阻塞和终止等状态，确保任务执行的有序性。

#### 任务管理类图
```mermaid
classDiagram
class TaskService {
+star_task(remote_addr, scanUrl, host, headers, body, options) BaseResponseMsg
+delete_task(taskid) BaseResponseMsg
+list_task() BaseResponseMsg
+kill_task(taskid) BaseResponseMsg
+stop_task(taskid) BaseResponseMsg
+start_task_with_taskid(taskid) BaseResponseMsg
+flush_task() BaseResponseMsg
+find_task_by_urlPath(urlPath) list[Task]
+find_task_by_bodyKeyWord(requestBodyKeyWord) list[Task]
+find_task_by_KeyWord(keyword) BaseResponseMsg
+find_task_by_header_keyword(headerKeyWord) list[Task]
+find_task_by_requestHost(requestHost) list[Task]
+find_task_log_by_taskid(taskid) BaseResponseMsg
+get_payload_detail_by_task_id(taskId) BaseResponseMsg
+get_task_http_request_info(taskId) BaseResponseMsg
+get_task_scan_options(taskId) BaseResponseMsg
+get_task_errors_by_taskId(taskId) BaseResponseMsg
}
class Task {
-status TaskStatus
-start_datetime datetime
-taskid str
-scanUrl str
-host str
-headers list[str]
-body str
-remote_addr str
-process Popen
-output_directory str
-options AttribDict
-_original_options AttribDict
-_header_rules_applied bool
+initialize_options(taskid)
+set_option(option, value)
+get_option(option)
+get_options()
+reset_options()
+apply_header_rules()
+engine_start()
+engine_stop()
+engine_process()
+engine_kill()
+engine_get_id()
+engine_get_returncode()
+engine_has_terminated()
}
TaskService --> Task : "管理"
```

**图示来源**
- [taskService.py](file://src/backEnd/service/taskService.py#L1-L531)
- [Task.py](file://src/backEnd/model/Task.py#L1-L206)

### 请求头规则管理组件分析
请求头规则管理组件提供灵活的请求头处理机制，支持持久化规则和会话级别规则两种模式。持久化规则存储在数据库中，适用于全局生效的请求头配置；会话级别规则存储在内存中，适用于临时性的请求头修改。系统支持多种替换策略，包括替换、追加、前置和条件性替换。

#### 请求头处理流程图
```mermaid
flowchart TD
Start([开始处理请求头]) --> Normalize["将请求头列表转换为字典格式"]
Normalize --> ApplyPersistent["应用持久化规则"]
ApplyPersistent --> ApplySession["应用会话级别规则"]
ApplySession --> Format["将字典转换回列表格式"]
Format --> End([返回处理结果])
ApplyPersistent --> |按优先级排序| SortRules["规则优先级排序"]
SortRules --> ProcessRules["逐个处理规则"]
ProcessRules --> |验证名称| ValidateName{"名称有效?"}
ValidateName --> |是| CheckCondition["检查匹配条件"]
ValidateName --> |否| SkipRule["跳过规则"]
CheckCondition --> |匹配| ApplyStrategy["应用替换策略"]
CheckCondition --> |不匹配| SkipRule
ApplyStrategy --> UpdateHeader["更新请求头值"]
ApplySession --> |过滤过期| FilterExpired["移除已过期会话头"]
FilterExpired --> SortSession["按优先级排序"]
SortSession --> ProcessSession["逐个处理会话头"]
ProcessSession --> |验证名称| ValidateSessionName{"名称有效?"}
ValidateSessionName --> |是| UpdateSessionHeader["更新会话请求头"]
ValidateSessionName --> |否| SkipSession["跳过会话头"]
```

**图示来源**
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L1-L799)
- [header_processor.py](file://src/backEnd/utils/header_processor.py#L1-L241)

## 依赖分析
系统各组件之间存在明确的依赖关系。API路由依赖于服务层实现业务逻辑，服务层依赖于数据模型和工具模块。任务服务和请求头规则服务通过DataStore共享数据状态，避免了直接耦合。认证模块作为独立组件，通过依赖注入方式集成到各个API端点中，确保认证逻辑的统一性。

```mermaid
graph TD
A[admin.py] --> B[taskService.py]
A --> C[headerRuleService.py]
A --> D[auth.py]
B --> E[Task.py]
B --> F[DataStore.py]
C --> G[PersistentHeaderRule.py]
C --> H[SessionHeader.py]
C --> I[header_processor.py]
C --> F
I --> J[ReplaceStrategy]
```

**图示来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py#L1-L117)
- [taskService.py](file://src/backEnd/service/taskService.py#L1-L531)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L1-L799)

## 性能考虑
系统在设计时充分考虑了性能因素。任务管理采用异步处理模式，避免阻塞主线程。请求头规则处理在任务创建时一次性完成，减少运行时开销。数据库操作使用连接池管理，提高数据访问效率。内存数据存储(DataStore)采用线程锁保护，确保多线程环境下的数据一致性，同时最小化锁竞争。

## 健康检查端点
新增了`/api/health`端点，用于前端监控后端服务的健康状态。该端点返回服务的运行状态、版本信息和运行时长，帮助前端应用判断后端服务是否可用。

### 健康检查API详情
- **HTTP方法**: GET
- **URL路径**: `/api/health`
- **认证要求**: 无（无需Bearer Token）
- **响应格式**: JSON

### 请求示例
```bash
curl -X GET "http://localhost:8775/api/health"
```

### 响应示例
```json
{
  "code": 200,
  "success": true,
  "message": "success",
  "data": {
    "status": "healthy",
    "timestamp": 1700000000000,
    "version": "0.0.1",
    "uptime": 3600
  }
}
```

### 响应字段说明
- **status**: 服务状态，"healthy"表示服务正常
- **timestamp**: 当前时间戳（毫秒）
- **version**: API版本号
- **uptime**: 服务运行时长（秒）

### 使用场景
前端应用可以定期调用此端点来：
1. 检测后端服务是否可用
2. 显示服务版本信息
3. 监控服务运行时长
4. 在服务异常时显示友好的错误提示

**组件来源**
- [app.py](file://src/backEnd/app.py#L46-L64)

## 故障排除指南
常见问题包括认证失败、任务创建异常和请求头处理错误。认证失败通常由于缺少Bearer Token或IP地址不在白名单中。任务创建异常可能源于sqlmap配置错误或资源不足。请求头处理错误多由无效的请求头名称或格式引起。系统日志记录了详细的处理过程，有助于快速定位问题根源。对于健康检查相关问题，如果`/api/health`端点无法访问，可能的原因包括：
- 后端服务未启动
- 网络连接问题
- 防火墙阻止了端口访问
- 服务进程崩溃

**故障排除来源**
- [auth.py](file://src/backEnd/utils/auth.py#L1-L22)
- [taskService.py](file://src/backEnd/service/taskService.py#L1-L531)
- [header_processor.py](file://src/backEnd/utils/header_processor.py#L1-L241)
- [app.py](file://src/backEnd/app.py#L46-L64)

## 结论
该通用API提供了完整的任务管理和请求头规则管理功能，通过清晰的分层架构和模块化设计，实现了高内聚低耦合的系统结构。API设计遵循RESTful原则，接口清晰易用。安全机制完善，通过认证和输入验证防止滥用。系统具备良好的扩展性，可方便地添加新的功能模块。新增的健康检查端点增强了系统的可监控性，为前端应用提供了可靠的服务状态检测机制。