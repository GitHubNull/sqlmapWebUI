# Chrome扩展API

<cite>
**本文档引用的文件**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [TaskRequest.py](file://src/backEnd/model/requestModel/TaskRequest.py)
- [BaseResponseMsg.py](file://src/backEnd/model/BaseResponseMsg.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [Task.py](file://src/backEnd/model/Task.py)
- [header_processor.py](file://src/backEnd/utils/header_processor.py)
</cite>

## 目录
1. [简介](#简介)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [架构概述](#架构概述)
5. [详细组件分析](#详细组件分析)
6. [依赖分析](#依赖分析)
7. [性能考虑](#性能考虑)
8. [故障排除指南](#故障排除指南)
9. [结论](#结论)
10. [附录](#附录)（如有必要）

## 简介
本文档详细说明了Chrome浏览器扩展与后端系统集成的API接口，重点介绍`chromeExApi/admin.py`中定义的专用端点。这些API支持请求捕获、请求头注入、任务创建和状态同步等功能。文档详细描述了`POST /api/chrome/capture`端点，该端点用于接收从Chrome扩展发送的HTTP请求数据并将其转换为扫描任务。同时说明了如何处理扩展发送的自定义请求头和认证信息，并提供了完整的HTTP方法、URL路径、请求体模式和响应格式说明。

## 项目结构
项目采用分层架构设计，主要分为API层、模型层和服务层。API层位于`src/backEnd/api`目录下，包含`chromeExApi`和`burpSuiteExApi`两个子模块，分别处理Chrome扩展和Burp Suite扩展的请求。模型层位于`src/backEnd/model`目录下，定义了数据结构和响应消息格式。服务层位于`src/backEnd/service`目录下，实现了核心业务逻辑。

```mermaid
graph TD
subgraph "API层"
chromeExApi["chromeExApi/admin.py"]
burpSuiteExApi["burpSuiteExApi/admin.py"]
end
subgraph "模型层"
TaskRequest["model/requestModel/TaskRequest.py"]
BaseResponseMsg["model/BaseResponseMsg.py"]
Task["model/Task.py"]
end
subgraph "服务层"
taskService["service/taskService.py"]
headerRuleService["service/headerRuleService.py"]
end
subgraph "工具层"
header_processor["utils/header_processor.py"]
auth["utils/auth.py"]
end
chromeExApi --> taskService
burpSuiteExApi --> taskService
taskService --> Task
taskService --> headerRuleService
headerRuleService --> header_processor
```

**图示来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [TaskRequest.py](file://src/backEnd/model/requestModel/TaskRequest.py)
- [taskService.py](file://src/backEnd/service/taskService.py)

**本节来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [TaskRequest.py](file://src/backEnd/model/requestModel/TaskRequest.py)

## 核心组件
核心组件包括Chrome扩展API端点、任务服务和请求头处理器。Chrome扩展API提供了一系列管理任务的端点，如创建、删除、启动、停止任务等。任务服务负责协调任务的生命周期管理，包括任务创建、状态更新和结果查询。请求头处理器负责在扫描前应用持久化规则和会话性请求头，确保请求头规则立即生效。

**本节来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [header_processor.py](file://src/backEnd/utils/header_processor.py)

## 架构概述
系统采用FastAPI框架构建RESTful API，通过模块化设计实现了Chrome扩展与后端的无缝集成。Chrome扩展通过API端点发送HTTP请求数据，后端系统将其转换为sqlmap扫描任务。系统实现了完整的认证机制，所有敏感操作都需要Bearer Token或API Key认证。

```mermaid
graph TB
subgraph "前端"
ChromeExtension[Chrome扩展]
end
subgraph "后端"
API[API服务器]
Auth[认证服务]
TaskService[任务服务]
Database[(数据库)]
end
ChromeExtension --> API
API --> Auth
API --> TaskService
TaskService --> Database
TaskService --> sqlmap[sqlmap引擎]
```

**图示来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)

## 详细组件分析

### Chrome扩展API分析
Chrome扩展API提供了丰富的端点来管理扫描任务，支持任务的全生命周期管理。

#### API端点类图
```mermaid
classDiagram
class ChromeAdminAPI {
+delete_task(taskDeleteRequest)
+kill_task(taskDeleteRequest)
+list_task()
+start_start_with_taskid(taskDeleteRequest)
+stop_task(taskStopRequest)
+stop_flush()
+find_task_by_urlPath(taskFindByUrlPathRequest)
+find_task_by_bodyKeyWord(taskFindByBodyKeyWordRequest)
+find_task_by_headerKeyWord(taskFindByHeaderKeyWordRequest)
+get_logs_by_taskid(taskLogQueryRequest)
+get_payload_detail_by_task_id(taskId)
+get_task_http_request_info(taskId)
+get_task_by_keyword(keyword)
+get_task_scan_options_by_taskId(taskId)
+get_task_errors_by_taskId(taskId)
}
class TaskService {
+star_task(remote_addr, scanUrl, host, headers, body, options)
+delete_task(taskid)
+list_task()
+kill_task(taskid)
+stop_task(taskid)
+start_task_with_taskid(taskid)
+flush_task()
+find_task_by_urlPath(urlPath)
+find_task_by_bodyKeyWord(requestBodyKeyWord)
+find_task_by_KeyWord(keyword)
+find_task_by_header_keyword(headerKeyWord)
+find_task_by_requestHost(requestHost)
+find_task_log_by_taskid(taskid)
+get_payload_detail_by_task_id(taskId)
+get_task_http_request_info(taskId)
+get_task_scan_options(taskId)
+get_task_errors_by_taskId(taskId)
}
ChromeAdminAPI --> TaskService : "使用"
```

**图示来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)

#### 任务创建序列图
```mermaid
sequenceDiagram
participant Extension as "Chrome扩展"
participant API as "API服务器"
participant Service as "任务服务"
participant Task as "任务"
participant Processor as "请求头处理器"
Extension->>API : POST /api/chrome/capture
API->>API : 验证认证信息
API->>Service : star_task(scanUrl, host, headers, body, options)
Service->>Task : 创建新任务
Task->>Processor : apply_header_rules()
Processor->>Processor : 应用持久化规则
Processor->>Processor : 应用会话性请求头
Processor-->>Task : 返回处理后的请求头
Task-->>Service : 任务初始化完成
Service-->>API : 返回任务ID
API-->>Extension : {taskid, engineid}
Note over Extension,Task : 任务创建流程
```

**图示来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [Task.py](file://src/backEnd/model/Task.py)
- [header_processor.py](file://src/backEnd/utils/header_processor.py)

#### 请求头处理流程图
```mermaid
flowchart TD
Start([开始]) --> Normalize["将请求头列表转换为字典格式"]
Normalize --> ApplyPersistent["应用持久化规则"]
ApplyPersistent --> ApplySession["应用会话性请求头"]
ApplySession --> Format["将字典转换回列表格式"]
Format --> End([结束])
subgraph "持久化规则处理"
ApplyPersistent --> SortRules["按优先级排序规则"]
SortRules --> LoopRules["遍历每个规则"]
LoopRules --> CheckActive{"规则是否激活?"}
CheckActive --> |否| NextRule
CheckActive --> |是| ValidateName["验证请求头名称"]
ValidateName --> MatchCondition{"匹配条件?"}
MatchCondition --> |否| NextRule
MatchCondition --> |是| ApplyStrategy["应用替换策略"]
ApplyStrategy --> UpdateHeaders["更新请求头"]
UpdateHeaders --> LogApplied["记录应用的规则"]
LogApplied --> NextRule["处理下一个规则"]
end
subgraph "会话性请求头处理"
ApplySession --> FilterExpired["过滤已过期的会话头"]
FilterExpired --> SortHeaders["按优先级排序"]
SortHeaders --> LoopHeaders["遍历每个会话头"]
LoopHeaders --> ApplyHeader["应用会话头"]
ApplyHeader --> LogSession["记录应用的会话头"]
LogSession --> NextHeader["处理下一个会话头"]
end
```

**图示来源**
- [header_processor.py](file://src/backEnd/utils/header_processor.py)
- [Task.py](file://src/backEnd/model/Task.py)

**本节来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [Task.py](file://src/backEnd/model/Task.py)
- [header_processor.py](file://src/backEnd/utils/header_processor.py)

### 请求模型分析
请求模型定义了API交互的数据结构，确保前后端数据的一致性。

#### 请求模型类图
```mermaid
classDiagram
class TaskAddRequest {
+scanUrl : str
+host : str
+headers : list
+body : str
+options : dict
}
class TaskDeleteRequest {
+taskid : str
}
class TaskStopRequest {
+taskid : str
}
class TaskFindByUrlPathRequest {
+urlPath : str
}
class TaskFindByBodyKeyWordRequest {
+bodyKeyWord : str
}
class TaskFindByHeaderKeyWordRequest {
+headerKeyWord : str
}
class TaskLogQueryRequest {
+taskId : str
}
class BaseResponseMsg {
+data : any
+msg : str
+success : bool
+code : int
}
TaskAddRequest <|-- TaskUpdateRequest
TaskDeleteRequest <|-- TaskStopRequest
TaskDeleteRequest <|-- TaskLogQueryRequest
```

**图示来源**
- [TaskRequest.py](file://src/backEnd/model/requestModel/TaskRequest.py)
- [BaseResponseMsg.py](file://src/backEnd/model/BaseResponseMsg.py)

**本节来源**
- [TaskRequest.py](file://src/backEnd/model/requestModel/TaskRequest.py)
- [BaseResponseMsg.py](file://src/backEnd/model/BaseResponseMsg.py)

## 依赖分析
系统各组件之间存在明确的依赖关系，确保了功能的模块化和可维护性。

```mermaid
graph TD
admin[chromeExApi/admin.py] --> taskService[service/taskService.py]
taskService --> Task[model/Task.py]
taskService --> DataStore[model/DataStore.py]
taskService --> TaskStatus[model/TaskStatus.py]
taskService --> BaseResponseMsg[model/BaseResponseMsg.py]
Task --> header_processor[utils/header_processor.py]
Task --> headerRuleService[service/headerRuleService.py]
headerRuleService --> header_processor
header_processor --> PersistentHeaderRule[model/PersistentHeaderRule.py]
header_processor --> SessionHeader[model/SessionHeader.py]
style admin fill:#f9f,stroke:#333
style taskService fill:#bbf,stroke:#333
style Task fill:#f96,stroke:#333
```

**图示来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [Task.py](file://src/backEnd/model/Task.py)
- [header_processor.py](file://src/backEnd/utils/header_processor.py)

**本节来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [Task.py](file://src/backEnd/model/Task.py)
- [header_processor.py](file://src/backEnd/utils/header_processor.py)

## 性能考虑
系统在设计时充分考虑了性能因素，通过多种机制确保高效运行。任务管理使用线程锁确保数据一致性，避免并发访问问题。请求头处理在任务创建时一次性完成，避免了重复处理的开销。数据库查询优化了索引使用，确保任务列表和日志查询的高效性。系统还实现了任务池清理功能，定期清理已完成的任务，释放系统资源。

## 故障排除指南
当遇到API调用问题时，可以参考以下常见问题的解决方案：

1. **认证失败**：确保请求头中包含有效的Bearer Token或API Key
2. **任务创建失败**：检查请求体格式是否符合TaskAddRequest定义，特别是taskid长度必须为16位
3. **请求头处理异常**：检查持久化规则和会话性请求头的配置是否正确
4. **数据库连接问题**：确认数据库服务正常运行，连接字符串配置正确
5. **sqlmap引擎启动失败**：检查python环境和sqlmap依赖是否正确安装

**本节来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [Task.py](file://src/backEnd/model/Task.py)

## 结论
本文档详细介绍了Chrome扩展API的设计和实现，涵盖了从请求捕获到任务管理的完整流程。系统通过模块化设计实现了高内聚低耦合的架构，确保了代码的可维护性和可扩展性。API设计遵循RESTful原则，提供了清晰的端点和数据结构定义。安全方面实现了完整的认证机制，确保系统访问的安全性。整体架构能够有效支持Chrome扩展与后端系统的集成，为用户提供强大的扫描功能。

## 附录

### API端点表格
| 端点 | HTTP方法 | 描述 | 认证要求 |
|------|---------|------|---------|
| /api/chrome/admin/task/delete | DELETE | 删除任务 | Bearer Token |
| /api/chrome/admin/task/kill | PUT | 终止任务 | Bearer Token |
| /api/chrome/admin/task/list | GET | 列出所有任务 | Bearer Token |
| /api/chrome/admin/task/startBlocked | PUT | 启动被阻塞的任务 | Bearer Token |
| /api/chrome/admin/task/stop | PUT | 停止任务 | Bearer Token |
| /api/chrome/admin/task/flush | PATCH | 清理任务池 | Bearer Token |

### 状态码表格
| 状态码 | 含义 | 描述 |
|-------|------|------|
| 200 | OK | 请求成功 |
| 400 | Bad Request | 请求格式错误 |
| 404 | Not Found | 资源不存在 |
| 500 | Internal Server Error | 服务器内部错误 |
| 503 | Service Unavailable | 服务不可用 |

**本节来源**
- [admin.py](file://src/backEnd/api/chromeExApi/admin.py)
- [BaseResponseMsg.py](file://src/backEnd/model/BaseResponseMsg.py)