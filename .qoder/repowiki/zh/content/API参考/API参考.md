# API参考

<cite>
**本文档中引用的文件**
- [authController.py](file://src/backEnd/api/commonApi/authController.py)
- [configController.py](file://src/backEnd/api/commonApi/configController.py)
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py)
- [webTaskController.py](file://src/backEnd/api/commonApi/webTaskController.py)
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py)
- [BaseResponseMsg.py](file://src/backEnd/model/BaseResponseMsg.py)
- [TaskRequest.py](file://src/backEnd/model/requestModel/TaskRequest.py)
- [taskService.py](file://src/backEnd/service/taskService.py)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py)
- [app.py](file://src/backEnd/app.py)
- [config.py](file://src/backEnd/config.py)
</cite>

## 目录
1. [简介](#简介)
2. [认证API](#认证api)
3. [配置管理API](#配置管理api)
4. [请求头管理API](#请求头管理api)
5. [扫描配置预设API](#扫描配置预设api)
6. [Web任务管理API](#web任务管理api)
7. [系统信息API](#系统信息api)
8. [API通用规范](#api通用规范)
9. [客户端调用示例](#客户端调用示例)
10. [错误处理指南](#错误处理指南)

## 简介

sqlmapWebUI后端提供了一套完整的RESTful API接口，用于管理和控制SQL注入扫描任务。本API参考文档详细介绍了所有公共API接口，包括HTTP方法、URL路径、请求参数、请求体结构、响应格式和状态码。

API设计遵循RESTful原则，使用JSON格式进行数据交换，所有响应都遵循统一的响应格式。API主要分为以下几类：
- 认证控制器：处理用户认证和令牌管理
- 配置控制器：管理系统配置和临时文件目录
- 请求头控制器：管理持久化和会话性请求头规则
- 扫描配置预设控制器：管理扫描配置预设
- Web任务控制器：处理Web端扫描任务的创建和管理

当前系统版本为1.7.9，API采用本地单机模式，不需要真正的用户认证。所有API接口都通过`/api`前缀访问，由FastAPI框架提供支持。

**Section sources**
- [app.py](file://src/backEnd/app.py#L1-L80)
- [config.py](file://src/backEnd/config.py#L1-L8)

## 认证API

认证API提供用户登录、令牌刷新和认证检查功能。在本地单机模式下，这些接口主要用于演示和未来远程访问模式的扩展。

### 登录接口

**HTTP方法**: `POST`  
**URL路径**: `/api/auth/login`

#### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| username | string | 是 | 用户名 |
| password | string | 是 | 密码 |

#### 请求体结构
```json
{
  "username": "admin",
  "password": "password123"
}
```

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "登录成功",
  "data": {
    "token": "local_token_20251221153427",
    "userInfo": {
      "username": "admin",
      "email": "admin@local",
      "role": "admin"
    }
  }
}
```

#### 状态码
- `200`: 登录成功
- `500`: 登录失败

**Section sources**
- [authController.py](file://src/backEnd/api/commonApi/authController.py#L40-L69)

### 令牌刷新接口

**HTTP方法**: `POST`  
**URL路径**: `/api/auth/refresh`

#### 请求参数
无请求体参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "令牌刷新成功",
  "data": {
    "token": "local_token_20251221153430",
    "expires_in": 86400
  }
}
```

#### 状态码
- `200`: 令牌刷新成功
- `500`: 令牌刷新失败

**Section sources**
- [authController.py](file://src/backEnd/api/commonApi/authController.py#L81-L102)

### 认证检查接口

**HTTP方法**: `GET`  
**URL路径**: `/api/auth/check-required`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "检查成功",
  "data": {
    "required": false,
    "mode": "local",
    "version": "1.7.9"
  }
}
```

#### 状态码
- `200`: 检查成功
- `500`: 检查失败

**Section sources**
- [authController.py](file://src/backEnd/api/commonApi/authController.py#L114-L140)

## 配置管理API

配置管理API用于管理系统配置，特别是HTTP请求临时文件目录的设置和管理。

### 获取临时文件目录配置

**HTTP方法**: `GET`  
**URL路径**: `/api/config/temp-dir`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "success",
  "data": {
    "currentTempDir": "E:\\devs\\python-devs\\pycharm-devs\\sqlmapWebUI\\temp\\http_requests",
    "defaultTempDir": "E:\\devs\\python-devs\\pycharm-devs\\sqlmapWebUI\\temp\\http_requests",
    "isCustom": false
  }
}
```

#### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [configController.py](file://src/backEnd/api/commonApi/configController.py#L34-L57)

### 设置临时文件目录

**HTTP方法**: `POST`  
**URL路径**: `/api/config/temp-dir`

#### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| tempDir | string | 否 | 临时文件目录路径，为空时恢复默认值 |

#### 请求体结构
```json
{
  "tempDir": "C:\\temp\\http_requests"
}
```

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "Temp directory set to C:\\temp\\http_requests",
  "data": {
    "currentTempDir": "C:\\temp\\http_requests",
    "defaultTempDir": "E:\\devs\\python-devs\\pycharm-devs\\sqlmapWebUI\\temp\\http_requests",
    "isCustom": true
  }
}
```

#### 状态码
- `200`: 设置成功
- `400`: 目录不可写或创建失败
- `500`: 设置失败

**Section sources**
- [configController.py](file://src/backEnd/api/commonApi/configController.py#L67-L129)

### 重置临时文件目录

**HTTP方法**: `POST`  
**URL路径**: `/api/config/temp-dir/reset`

#### 请求参数
无请求体参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "Temp directory reset to default",
  "data": {
    "currentTempDir": "E:\\devs\\python-devs\\pycharm-devs\\sqlmapWebUI\\temp\\http_requests",
    "defaultTempDir": "E:\\devs\\python-devs\\pycharm-devs\\sqlmapWebUI\\temp\\http_requests",
    "isCustom": false
  }
}
```

#### 状态码
- `200`: 重置成功
- `500`: 重置失败

**Section sources**
- [configController.py](file://src/backEnd/api/commonApi/configController.py#L140-L164)

## 请求头管理API

请求头管理API提供对持久化请求头规则和会话性请求头的全面管理功能，包括创建、读取、更新、删除和批量操作。

### 健康检查

**HTTP方法**: `GET`  
**URL路径**: `/api/commonApi/header/headers/ping`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "Chrome请求头管理服务正常运行（本地模式）",
  "data": {
    "service": "chrome_headers",
    "status": "healthy",
    "timestamp": "2025-12-21T15:34:30Z",
    "version": "1.0.0",
    "capabilities": [
      "persistent_rules",
      "session_headers",
      "batch_operations",
      "header_preview",
      "stats"
    ]
  }
}
```

#### 状态码
- `200`: 服务健康
- `503`: 服务异常

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L32-L57)

### 持久化请求头规则管理

#### 创建持久化请求头规则

**HTTP方法**: `POST`  
**URL路径**: `/api/commonApi/header/persistent-header-rules`

##### 请求参数
请求体包含`PersistentHeaderRuleCreate`对象。

##### 请求体结构
```json
{
  "name": "X-Forwarded-For",
  "header_name": "X-Forwarded-For",
  "header_value": "127.0.0.1",
  "replace_strategy": "REPLACE",
  "match_condition": "ALWAYS",
  "priority": 100,
  "is_active": true,
  "scope": {
    "include_urls": ["https://example.com"],
    "exclude_urls": [],
    "include_methods": ["GET", "POST"],
    "exclude_methods": []
  }
}
```

##### 响应格式
成功响应（HTTP 201）：
```json
{
  "code": 201,
  "success": true,
  "message": "持久化请求头规则创建成功",
  "data": {
    "id": 1,
    "name": "X-Forwarded-For",
    "header_name": "X-Forwarded-For",
    "header_value": "127.0.0.1",
    "replace_strategy": "REPLACE",
    "match_condition": "ALWAYS",
    "priority": 100,
    "is_active": true,
    "scope": {
      "include_urls": ["https://example.com"],
      "exclude_urls": [],
      "include_methods": ["GET", "POST"],
      "exclude_methods": []
    },
    "created_at": "2025-12-21 15:34:30",
    "updated_at": "2025-12-21 15:34:30"
  }
}
```

##### 状态码
- `201`: 创建成功
- `400`: 数据验证失败
- `500`: 创建失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L69-L77)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L74-L167)

#### 获取持久化请求头规则列表

**HTTP方法**: `GET`  
**URL路径**: `/api/commonApi/header/persistent-header-rules`

##### 请求参数
| 参数 | 类型 | 必需 | 默认值 | 描述 |
|------|------|------|--------|------|
| active_only | boolean | 否 | true | 只获取活跃规则 |

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "查询成功",
  "data": {
    "rules": [
      {
        "id": 1,
        "name": "X-Forwarded-For",
        "header_name": "X-Forwarded-For",
        "header_value": "127.0.0.1",
        "replace_strategy": "REPLACE",
        "match_condition": "ALWAYS",
        "priority": 100,
        "is_active": true,
        "scope": {
          "include_urls": ["https://example.com"],
          "exclude_urls": [],
          "include_methods": ["GET", "POST"],
          "exclude_methods": []
        },
        "created_at": "2025-12-21 15:34:30",
        "updated_at": "2025-12-21 15:34:30"
      }
    ],
    "total_count": 1
  }
}
```

##### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L82-L89)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L177-L252)

#### 根据ID获取持久化请求头规则

**HTTP方法**: `GET`  
**URL路径**: `/api/commonApi/header/persistent-header-rules/{rule_id}`

##### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| rule_id | integer | 是 | 规则ID |

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "查询成功",
  "data": {
    "id": 1,
    "name": "X-Forwarded-For",
    "header_name": "X-Forwarded-For",
    "header_value": "127.0.0.1",
    "replace_strategy": "REPLACE",
    "match_condition": "ALWAYS",
    "priority": 100,
    "is_active": true,
    "scope": {
      "include_urls": ["https://example.com"],
      "exclude_urls": [],
      "include_methods": ["GET", "POST"],
      "exclude_methods": []
    },
    "created_at": "2025-12-21 15:34:30",
    "updated_at": "2025-12-21 15:34:30"
  }
}
```

##### 状态码
- `200`: 获取成功
- `404`: 规则不存在
- `500`: 获取失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L95-L103)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L262-L327)

#### 更新持久化请求头规则

**HTTP方法**: `PUT`  
**URL路径**: `/api/commonApi/header/persistent-header-rules/{rule_id}`

##### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| rule_id | integer | 是 | 规则ID |

请求体包含`PersistentHeaderRuleUpdate`对象。

##### 请求体结构
```json
{
  "name": "X-Forwarded-For-Updated",
  "header_value": "192.168.1.1",
  "priority": 200,
  "is_active": false
}
```

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "持久化请求头规则更新成功",
  "data": {
    "id": 1,
    "name": "X-Forwarded-For-Updated",
    "header_name": "X-Forwarded-For",
    "header_value": "192.168.1.1",
    "replace_strategy": "REPLACE",
    "match_condition": "ALWAYS",
    "priority": 200,
    "is_active": false,
    "scope": {
      "include_urls": ["https://example.com"],
      "exclude_urls": [],
      "include_methods": ["GET", "POST"],
      "exclude_methods": []
    },
    "created_at": "2025-12-21 15:34:30",
    "updated_at": "2025-12-21 15:35:00"
  }
}
```

##### 状态码
- `200`: 更新成功
- `400`: 数据验证失败
- `404`: 规则不存在
- `500`: 更新失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L108-L117)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L338-L470)

#### 删除持久化请求头规则

**HTTP方法**: `DELETE`  
**URL路径**: `/api/commonApi/header/persistent-header-rules/{rule_id}`

##### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| rule_id | integer | 是 | 规则ID |

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "持久化请求头规则 'X-Forwarded-For' 删除成功",
  "data": null
}
```

##### 状态码
- `200`: 删除成功
- `404`: 规则不存在
- `500`: 删除失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L122-L132)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L481-L523)

### 会话性请求头管理

#### 设置会话性请求头

**HTTP方法**: `POST`  
**URL路径**: `/api/commonApi/header/session-headers`

##### 请求参数
请求体包含`SessionHeaderBatchCreate`对象。

##### 请求体结构
```json
{
  "headers": [
    {
      "header_name": "X-Custom-Header",
      "header_value": "custom-value",
      "replace_strategy": "REPLACE",
      "priority": 100,
      "is_active": true,
      "ttl": 3600,
      "scope": {
        "include_urls": ["https://example.com"],
        "exclude_urls": [],
        "include_methods": ["GET", "POST"],
        "exclude_methods": []
      }
    }
  ]
}
```

##### 响应格式
全部成功（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "会话性请求头设置成功",
  "data": {
    "client_ip": "127.0.0.1",
    "headers_count": 1,
    "total_headers": 1
  }
}
```

部分成功（HTTP 206）：
```json
{
  "code": 206,
  "success": true,
  "message": "部分会话性请求头设置成功 (1/2)",
  "data": {
    "client_ip": "127.0.0.1",
    "headers_count": 1,
    "total_headers": 2
  }
}
```

##### 状态码
- `200`: 全部设置成功
- `206`: 部分设置成功
- `500`: 设置失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L136-L167)

#### 获取会话性请求头

**HTTP方法**: `GET`  
**URL路径**: `/api/commonApi/header/session-headers`

##### 请求参数
无请求参数。

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "查询成功",
  "data": {
    "client_ip": "127.0.0.1",
    "headers": [
      {
        "header_name": "X-Custom-Header",
        "header_value": "custom-value",
        "replace_strategy": "REPLACE",
        "priority": 100,
        "is_active": true,
        "ttl": 3600,
        "scope": {
          "include_urls": ["https://example.com"],
          "exclude_urls": [],
          "include_methods": ["GET", "POST"],
          "exclude_methods": []
        },
        "created_at": "2025-12-21 15:34:30",
        "updated_at": "2025-12-21 15:34:30"
      }
    ],
    "total_count": 1
  }
}
```

##### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L174-L201)

#### 清除会话性请求头

**HTTP方法**: `DELETE`  
**URL路径**: `/api/commonApi/header/session-headers`

##### 请求参数
无请求体参数。

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "会话性请求头清除成功",
  "data": {
    "client_ip": "127.0.0.1"
  }
}
```

##### 状态码
- `200`: 清除成功
- `500`: 清除失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L208-L232)

#### 删除单个会话性请求头

**HTTP方法**: `DELETE`  
**URL路径**: `/api/commonApi/header/session-headers/{header_name}`

##### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| header_name | string | 是 | 请求头名称 |

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "会话性请求头删除成功",
  "data": {
    "client_ip": "127.0.0.1",
    "header_name": "X-Custom-Header"
  }
}
```

失败响应（HTTP 404）：
```json
{
  "code": 404,
  "success": false,
  "message": "没有找到指定的会话性请求头",
  "data": null
}
```

##### 状态码
- `200`: 删除成功
- `404`: 请求头不存在
- `500`: 删除失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L239-L264)

#### 更新单个会话性请求头

**HTTP方法**: `PUT`  
**URL路径**: `/api/commonApi/header/session-headers/{header_name}`

##### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| header_name | string | 是 | 请求头名称 |

请求体包含`SessionHeaderUpdateRequest`对象。

##### 请求体结构
```json
{
  "header_value": "new-value",
  "priority": 200,
  "is_active": false,
  "ttl": 7200
}
```

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "会话性请求头更新成功",
  "data": {
    "client_ip": "127.0.0.1",
    "header_name": "X-Custom-Header"
  }
}
```

失败响应（HTTP 404）：
```json
{
  "code": 404,
  "success": false,
  "message": "没有找到指定的会话性请求头",
  "data": null
}
```

##### 状态码
- `200`: 更新成功
- `404`: 请求头不存在
- `500`: 更新失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L280-L347)

### 请求头处理预览

**HTTP方法**: `POST`  
**URL路径**: `/api/commonApi/header/header-processing/preview`

#### 请求参数
请求体包含`HeaderPreviewRequest`对象。

#### 请求体结构
```json
{
  "headers": [
    "GET /api/users HTTP/1.1",
    "Host: example.com",
    "User-Agent: Mozilla/5.0"
  ],
  "target_url": "https://example.com/api/users"
}
```

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "预览成功",
  "data": {
    "original_headers": [
      "GET /api/users HTTP/1.1",
      "Host: example.com",
      "User-Agent: Mozilla/5.0"
    ],
    "processed_headers": [
      "GET /api/users HTTP/1.1",
      "Host: example.com",
      "User-Agent: Mozilla/5.0",
      "X-Forwarded-For: 127.0.0.1"
    ],
    "applied_rules": [
      "X-Forwarded-For"
    ],
    "applied_session_headers": []
  }
}
```

#### 状态码
- `200`: 预览成功
- `500`: 预览失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L360-L379)

### 系统统计信息

**HTTP方法**: `GET`  
**URL路径**: `/api/commonApi/header/header-management/stats`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "统计信息获取成功",
  "data": {
    "persistent_rules": {
      "total_count": 5,
      "active_count": 3
    },
    "session_headers": {
      "client_count": 1,
      "total_headers_count": 2,
      "active_headers_count": 2
    }
  }
}
```

#### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L386-L417)

### 批量操作接口

#### 批量解析请求头

**HTTP方法**: `POST`  
**URL路径**: `/api/commonApi/header/headers/parse`

##### 请求参数
请求体包含`HeaderBatchParseRequest`对象。

##### 请求体结构
```json
{
  "raw_text": "GET /api/users HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
  "format_hint": "raw_http",
  "default_priority": 100
}
```

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "解析成功",
  "data": {
    "success": true,
    "total_count": 3,
    "parsed_headers": [
      {
        "header_name": "GET /api/users HTTP/1.1",
        "header_value": "",
        "source_line": 1,
        "priority": 100
      },
      {
        "header_name": "Host",
        "header_value": "example.com",
        "source_line": 2,
        "priority": 100
      },
      {
        "header_name": "User-Agent",
        "header_value": "Mozilla/5.0",
        "source_line": 3,
        "priority": 100
      }
    ],
    "errors": [],
    "warnings": []
  }
}
```

##### 状态码
- `200`: 解析成功
- `400`: 解析失败
- `500`: 解析失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L428-L436)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L629-L667)

#### 批量创建持久化请求头规则

**HTTP方法**: `POST`  
**URL路径**: `/api/commonApi/header/persistent-header-rules/batch`

##### 请求参数
请求体包含`ParsedHeaderBatchCreateRequest`对象。

##### 请求体结构
```json
{
  "headers": [
    {
      "header_name": "X-Custom-1",
      "header_value": "value1",
      "source_line": 1,
      "priority": 100
    },
    {
      "header_name": "X-Custom-2",
      "header_value": "value2",
      "source_line": 2,
      "priority": 100
    }
  ],
  "rule_config": {
    "name_prefix": "BatchRule_",
    "replace_strategy": "REPLACE",
    "default_priority": 100,
    "is_active": true
  }
}
```

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "批量创建成功",
  "data": {
    "success": true,
    "total_count": 2,
    "success_count": 2,
    "failed_count": 0,
    "created_items": [
      {
        "id": 1,
        "name": "BatchRule_X-Custom-1_20251221153430",
        "header_name": "X-Custom-1",
        "header_value": "value1",
        "source_line": 1
      },
      {
        "id": 2,
        "name": "BatchRule_X-Custom-2_20251221153430",
        "header_name": "X-Custom-2",
        "header_value": "value2",
        "source_line": 2
      }
    ],
    "failed_items": [],
    "warnings": []
  }
}
```

##### 状态码
- `200`: 批量创建成功
- `400`: 批量创建失败
- `500`: 批量创建失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L441-L449)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L678-L797)

#### 批量创建会话性请求头

**HTTP方法**: `POST`  
**URL路径**: `/api/commonApi/header/session-headers/batch`

##### 请求参数
请求体包含`ParsedHeaderBatchCreateRequest`对象。

##### 请求体结构
```json
{
  "headers": [
    {
      "header_name": "X-Session-1",
      "header_value": "session-value1",
      "source_line": 1,
      "priority": 100
    },
    {
      "header_name": "X-Session-2",
      "header_value": "session-value2",
      "source_line": 2,
      "priority": 100
    }
  ],
  "rule_config": {
    "replace_strategy": "REPLACE",
    "default_priority": 100,
    "is_active": true,
    "ttl": 3600
  }
}
```

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "批量创建成功",
  "data": {
    "success": true,
    "total_count": 2,
    "success_count": 2,
    "failed_count": 0,
    "created_items": [
      {
        "header_name": "X-Session-1",
        "source_line": 1
      },
      {
        "header_name": "X-Session-2",
        "source_line": 2
      }
    ],
    "failed_items": [],
    "warnings": []
  }
}
```

##### 状态码
- `200`: 批量创建成功
- `400`: 批量创建失败
- `500`: 批量创建失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L454-L464)

#### 一体化批量创建请求头

**HTTP方法**: `POST`  
**URL路径**: `/api/commonApi/header/headers/batch-create`

##### 请求参数
请求体包含`HeaderBatchCreateRequest`对象。

##### 请求体结构
```json
{
  "raw_text": "X-Custom-1: value1\nX-Custom-2: value2",
  "format_hint": "simple",
  "default_priority": 100,
  "target_type": "PERSISTENT",
  "rule_config": {
    "name_prefix": "BatchRule_",
    "replace_strategy": "REPLACE",
    "default_priority": 100,
    "is_active": true
  }
}
```

##### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "一体化批量创建成功",
  "data": {
    "parse_result": {
      "success": true,
      "total_count": 2,
      "parsed_headers": [
        {
          "header_name": "X-Custom-1",
          "header_value": "value1",
          "source_line": 1,
          "priority": 100
        },
        {
          "header_name": "X-Custom-2",
          "header_value": "value2",
          "source_line": 2,
          "priority": 100
        }
      ],
      "errors": [],
      "warnings": []
    },
    "create_result": {
      "success": true,
      "total_count": 2,
      "success_count": 2,
      "failed_count": 0,
      "created_items": [
        {
          "id": 1,
          "name": "BatchRule_X-Custom-1_20251221153430",
          "header_name": "X-Custom-1",
          "header_value": "value1",
          "source_line": 1
        },
        {
          "id": 2,
          "name": "BatchRule_X-Custom-2_20251221153430",
          "header_name": "X-Custom-2",
          "header_value": "value2",
          "source_line": 2
        }
      ],
      "failed_items": [],
      "warnings": []
    }
  }
}
```

##### 状态码
- `200`: 一体化批量创建成功
- `400`: 一体化批量创建失败
- `500`: 一体化批量创建失败

**Section sources**
- [headerController.py](file://src/backEnd/api/commonApi/headerController.py#L469-L478)

## 扫描配置预设API

扫描配置预设API提供对扫描配置预设的管理功能，包括获取、创建、更新和删除预设配置。

### 获取所有预设配置列表

**HTTP方法**: `GET`  
**URL路径**: `/api/scan-preset/list`

#### 请求参数
| 参数 | 类型 | 必需 | 默认值 | 描述 |
|------|------|------|--------|------|
| include_inactive | boolean | 否 | false | 是否包含未激活的配置 |

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "获取成功",
  "data": {
    "presets": [
      {
        "id": 1,
        "name": "Default",
        "type": "DEFAULT",
        "options": {
          "level": 1,
          "risk": 1
        },
        "is_active": true,
        "created_at": "2025-12-21 15:34:30",
        "updated_at": "2025-12-21 15:34:30"
      }
    ],
    "total": 1,
    "default_preset": {
      "id": 1,
      "name": "Default",
      "type": "DEFAULT",
      "options": {
        "level": 1,
        "risk": 1
      },
      "is_active": true,
      "created_at": "2025-12-21 15:34:30",
      "updated_at": "2025-12-21 15:34:30"
    }
  }
}
```

#### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L23-L41)

### 获取配置选项

**HTTP方法**: `GET`  
**URL路径**: `/api/scan-preset/config-options`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "获取成功",
  "data": {
    "default": {
      "id": 1,
      "name": "Default",
      "type": "DEFAULT",
      "options": {
        "level": 1,
        "risk": 1
      },
      "is_active": true,
      "created_at": "2025-12-21 15:34:30",
      "updated_at": "2025-12-21 15:34:30"
    },
    "presets": [
      {
        "id": 2,
        "name": "High Risk",
        "type": "PRESET",
        "options": {
          "level": 5,
          "risk": 3
        },
        "is_active": true,
        "created_at": "2025-12-21 15:35:00",
        "updated_at": "2025-12-21 15:35:00"
      }
    ],
    "history": [
      {
        "id": 3,
        "name": "Previous Scan",
        "type": "HISTORY",
        "options": {
          "level": 3,
          "risk": 2
        },
        "is_active": true,
        "created_at": "2025-12-21 15:30:00",
        "updated_at": "2025-12-21 15:30:00"
      }
    ]
  }
}
```

#### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L46-L65)

### 获取默认配置

**HTTP方法**: `GET`  
**URL路径**: `/api/scan-preset/default`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "获取成功",
  "data": {
    "id": 1,
    "name": "Default",
    "type": "DEFAULT",
    "options": {
      "level": 1,
      "risk": 1
    },
    "is_active": true,
    "created_at": "2025-12-21 15:34:30",
    "updated_at": "2025-12-21 15:34:30"
  }
}
```

失败响应（HTTP 404）：
```json
{
  "code": 404,
  "success": false,
  "message": "默认配置不存在",
  "data": null
}
```

#### 状态码
- `200`: 获取成功
- `404`: 默认配置不存在
- `500`: 获取失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L71-L89)

### 更新默认配置

**HTTP方法**: `PUT`  
**URL路径**: `/api/scan-preset/default`

#### 请求参数
请求体包含options对象。

#### 请求体结构
```json
{
  "level": 3,
  "risk": 2
}
```

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "更新成功",
  "data": {
    "id": 1,
    "name": "Default",
    "type": "DEFAULT",
    "options": {
      "level": 3,
      "risk": 2
    },
    "is_active": true,
    "created_at": "2025-12-21 15:34:30",
    "updated_at": "2025-12-21 15:36:00"
  }
}
```

失败响应（HTTP 404）：
```json
{
  "code": 404,
  "success": false,
  "message": "更新失败",
  "data": null
}
```

#### 状态码
- `200`: 更新成功
- `404`: 更新失败
- `500`: 更新失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L96-L116)

### 获取常用配置列表

**HTTP方法**: `GET`  
**URL路径**: `/api/scan-preset/presets`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "获取成功",
  "data": {
    "presets": [
      {
        "id": 2,
        "name": "High Risk",
        "type": "PRESET",
        "options": {
          "level": 5,
          "risk": 3
        },
        "is_active": true,
        "created_at": "2025-12-21 15:35:00",
        "updated_at": "2025-12-21 15:35:00"
      }
    ],
    "total": 1
  }
}
```

#### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L122-L137)

### 获取历史配置列表

**HTTP方法**: `GET`  
**URL路径**: `/api/scan-preset/history`

#### 请求参数
| 参数 | 类型 | 必需 | 默认值 | 范围 | 描述 |
|------|------|------|--------|------|------|
| limit | integer | 否 | 20 | 1-100 | 返回数量限制 |

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "获取成功",
  "data": {
    "presets": [
      {
        "id": 3,
        "name": "Previous Scan",
        "type": "HISTORY",
        "options": {
          "level": 3,
          "risk": 2
        },
        "is_active": true,
        "created_at": "2025-12-21 15:30:00",
        "updated_at": "2025-12-21 15:30:00"
      }
    ],
    "total": 1
  }
}
```

#### 状态码
- `200`: 获取成功
- `500`: 获取失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L143-L159)

### 获取指定预设配置

**HTTP方法**: `GET`  
**URL路径**: `/api/scan-preset/{preset_id}`

#### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| preset_id | integer | 是 | 预设配置ID |

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "获取成功",
  "data": {
    "id": 2,
    "name": "High Risk",
    "type": "PRESET",
    "options": {
      "level": 5,
      "risk": 3
    },
    "is_active": true,
    "created_at": "2025-12-21 15:35:00",
    "updated_at": "2025-12-21 15:35:00"
  }
}
```

失败响应（HTTP 404）：
```json
{
  "code": 404,
  "success": false,
  "message": "配置不存在",
  "data": null
}
```

#### 状态码
- `200`: 获取成功
- `404`: 配置不存在
- `500`: 获取失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L165-L185)

### 创建新的预设配置

**HTTP方法**: `POST`  
**URL路径**: `/api/scan-preset`

#### 请求参数
请求体包含`ScanPresetCreate`对象。

#### 请求体结构
```json
{
  "name": "Custom Scan",
  "type": "PRESET",
  "options": {
    "level": 4,
    "risk": 3,
    "threads": 5
  },
  "is_active": true
}
```

#### 响应格式
成功响应（HTTP 201）：
```json
{
  "code": 201,
  "success": true,
  "message": "创建成功",
  "data": {
    "id": 4,
    "name": "Custom Scan",
    "type": "PRESET",
    "options": {
      "level": 4,
      "risk": 3,
      "threads": 5
    },
    "is_active": true,
    "created_at": "2025-12-21 15:37:00",
    "updated_at": "2025-12-21 15:37:00"
  }
}
```

失败响应（HTTP 400）：
```json
{
  "code": 400,
  "success": false,
  "message": "创建失败，配置名称可能已存在",
  "data": null
}
```

#### 状态码
- `201`: 创建成功
- `400`: 创建失败
- `500`: 创建失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L191-L211)

### 更新预设配置

**HTTP方法**: `PUT`  
**URL路径**: `/api/scan-preset/{preset_id}`

#### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| preset_id | integer | 是 | 预设配置ID |

请求体包含`ScanPresetUpdate`对象。

#### 请求体结构
```json
{
  "options": {
    "level": 5,
    "risk": 3,
    "threads": 10
  },
  "is_active": true
}
```

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "更新成功",
  "data": {
    "id": 4,
    "name": "Custom Scan",
    "type": "PRESET",
    "options": {
      "level": 5,
      "risk": 3,
      "threads": 10
    },
    "is_active": true,
    "created_at": "2025-12-21 15:37:00",
    "updated_at": "2025-12-21 15:38:00"
  }
}
```

失败响应（HTTP 404）：
```json
{
  "code": 404,
  "success": false,
  "message": "更新失败，配置不存在或名称冲突",
  "data": null
}
```

#### 状态码
- `200`: 更新成功
- `404`: 更新失败
- `500`: 更新失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L217-L238)

### 删除预设配置

**HTTP方法**: `DELETE`  
**URL路径**: `/api/scan-preset/{preset_id}`

#### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| preset_id | integer | 是 | 预设配置ID |

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "删除成功",
  "data": null
}
```

失败响应（HTTP 400）：
```json
{
  "code": 400,
  "success": false,
  "message": "删除失败，配置不存在或为默认配置",
  "data": null
}
```

#### 状态码
- `200`: 删除成功
- `400`: 删除失败
- `500`: 删除失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L244-L264)

### 添加到历史记录

**HTTP方法**: `POST`  
**URL路径**: `/api/scan-preset/history`

#### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| name | string | 是 | 配置名称 |

请求体包含options对象。

#### 请求体结构
```json
{
  "options": {
    "level": 3,
    "risk": 2
  }
}
```

#### 响应格式
成功响应（HTTP 201）：
```json
{
  "code": 201,
  "success": true,
  "message": "添加成功",
  "data": {
    "id": 5,
    "name": "Recent Scan",
    "type": "HISTORY",
    "options": {
      "level": 3,
      "risk": 2
    },
    "is_active": true,
    "created_at": "2025-12-21 15:39:00",
    "updated_at": "2025-12-21 15:39:00"
  }
}
```

失败响应（HTTP 400）：
```json
{
  "code": 400,
  "success": false,
  "message": "添加失败",
  "data": null
}
```

#### 状态码
- `201`: 添加成功
- `400`: 添加失败
- `500`: 添加失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L270-L294)

### 应用预设配置

**HTTP方法**: `POST`  
**URL路径**: `/api/scan-preset/{preset_id}/apply`

#### 请求参数
| 参数 | 类型 | 必需 | 描述 |
|------|------|------|------|
| preset_id | integer | 是 | 预设配置ID |

请求体包含`base_options`对象。

#### 请求体结构
```json
{
  "base_options": {
    "level": 1,
    "risk": 1
  }
}
```

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "应用成功",
  "data": {
    "options": {
      "level": 3,
      "risk": 2
    }
  }
}
```

#### 状态码
- `200`: 应用成功
- `500`: 应用失败

**Section sources**
- [scanPreset.py](file://src/backEnd/api/commonApi/scanPreset.py#L300-L321)

## Web任务管理API

Web任务管理API用于从Web界面提交扫描任务，与BurpSuite插件端共用相同的业务逻辑。

### 添加扫描任务

**HTTP方法**: `POST`  
**URL路径**: `/api/web/admin/task/add`

#### 请求参数
请求体包含`TaskAddRequest`对象。

#### 请求体结构
```json
{
  "scanUrl": "https://example.com/api/users",
  "host": "example.com",
  "headers": [
    "GET /api/users HTTP/1.1",
    "Host: example.com",
    "User-Agent: Mozilla/5.0"
  ],
  "body": "username=admin&password=123",
  "options": {
    "level": 3,
    "risk": 2
  }
}
```

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "success",
  "data": {
    "engineid": 12345,
    "taskid": "a1b2c3d4e5f6g7h8"
  }
}
```

失败响应（HTTP 400）：
```json
{
  "code": 400,
  "success": false,
  "message": "options is required",
  "data": null
}
```

#### 状态码
- `200`: 任务创建成功
- `400`: 请求参数错误
- `500`: 任务创建失败

**Section sources**
- [webTaskController.py](file://src/backEnd/api/commonApi/webTaskController.py#L19-L79)
- [taskService.py](file://src/backEnd/service/taskService.py#L58-L87)

## 系统信息API

系统信息API提供系统版本和健康状态检查功能。

### 获取系统版本

**HTTP方法**: `GET`  
**URL路径**: `/api/version`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "success",
  "data": {
    "version": "1.7.9"
  }
}
```

#### 状态码
- `200`: 获取成功

**Section sources**
- [app.py](file://src/backEnd/app.py#L49-L59)

### 健康检查

**HTTP方法**: `GET`  
**URL路径**: `/api/health`

#### 请求参数
无请求参数。

#### 响应格式
成功响应（HTTP 200）：
```json
{
  "code": 200,
  "success": true,
  "message": "success",
  "data": {
    "status": "healthy",
    "timestamp": 1734795270000,
    "version": "1.7.9",
    "uptime": 3600
  }
}
```

#### 状态码
- `200`: 服务健康

**Section sources**
- [app.py](file://src/backEnd/app.py#L61-L80)

## API通用规范

### 响应格式
所有API接口都返回统一的响应格式，包含以下字段：

| 字段 | 类型 | 描述 |
|------|------|------|
| code | integer | HTTP状态码 |
| success | boolean | 请求是否成功 |
| message | string | 响应消息 |
| data | object | 响应数据，具体内容根据接口而定 |

### 认证机制
当前系统运行在本地单机模式下，不需要真正的用户认证。`auth`相关接口主要用于未来远程访问模式的扩展。在本地模式下，来自`127.0.0.1`或`localhost`的请求被视为已认证。

### 安全考虑
- 所有API接口都通过CORS中间件配置了允许的来源，仅允许开发环境下的`localhost`和`127.0.0.1`访问。
- 系统使用模拟令牌进行认证，实际部署时需要替换为真正的JWT认证机制。
- 敏感操作（如删除、更新）都需要认证。

### API版本控制
当前API没有显式的版本控制，所有接口都位于`/api`前缀下。未来可以通过添加版本号前缀（如`/api/v1`）来实现版本控制。

### 向后兼容性
系统设计时考虑了向后兼容性：
- 新增功能通过添加新接口实现，不影响现有接口。
- 接口参数采用可选字段，确保旧客户端可以继续使用。
- 响应格式保持稳定，新增字段不会影响现有字段的解析。

**Section sources**
- [app.py](file://src/backEnd/app.py#L27-L34)
- [utils/auth.py](file://src/backEnd/utils/auth.py#L1-L23)

## 客户端调用示例

### Python调用示例
```python
import requests
import json

# 基础URL
base_url = "http://localhost:8775/api"

# 1. 检查认证需求
auth_check = requests.get(f"{base_url}/auth/check-required")
print("认证检查:", auth_check.json())

# 2. 获取系统版本
version = requests.get(f"{base_url}/version")
print("系统版本:", version.json())

# 3. 获取临时文件目录配置
temp_dir = requests.get(f"{base_url}/config/temp-dir")
print("临时目录配置:", temp_dir.json())

# 4. 创建扫描任务
task_data = {
    "scanUrl": "https://example.com/api/users",
    "host": "example.com",
    "headers": [
        "GET /api/users HTTP/1.1",
        "Host: example.com",
        "User-Agent: Mozilla/5.0"
    ],
    "body": "",
    "options": {
        "level": 3,
        "risk": 2
    }
}

task_response = requests.post(f"{base_url}/web/admin/task/add", json=task_data)
print("任务创建结果:", task_response.json())
```

### JavaScript调用示例
```javascript
// 基础URL
const baseUrl = 'http://localhost:8775/api';

// 封装API调用
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`${baseUrl}${endpoint}`, options);
        const result = await response.json();
        return result;
    } catch (error) {
        console.error('API调用失败:', error);
        return null;
    }
}

// 使用示例
async function example() {
    // 1. 检查系统健康状态
    const health = await apiCall('/health');
    console.log('健康状态:', health);
    
    // 2. 获取所有持久化请求头规则
    const rules = await apiCall('/commonApi/header/persistent-header-rules');
    console.log('请求头规则:', rules);
    
    // 3. 创建新的扫描任务
    const taskData = {
        scanUrl: 'https://example.com/api/users',
        host: 'example.com',
        headers: [
            'GET /api/users HTTP/1.1',
            'Host: example.com',
            'User-Agent: Mozilla/5.0'
        ],
        body: '',
        options: {
            level: 3,
            risk: 2
        }
    };
    
    const taskResult = await apiCall('/web/admin/task/add', 'POST', taskData);
    console.log('任务创建结果:', taskResult);
}

// 执行示例
example();
```

### curl调用示例
```bash
# 检查系统健康状态
curl -X GET "http://localhost:8775/api/health"

# 获取系统版本
curl -X GET "http://localhost:8775/api/version"

# 获取临时文件目录配置
curl -X GET "http://localhost:8775/api/config/temp-dir"

# 创建扫描任务
curl -X POST "http://localhost:8775/api/web/admin/task/add" \
  -H "Content-Type: application/json" \
  -d '{
    "scanUrl": "https://example.com/api/users",
    "host": "example.com",
    "headers": [
      "GET /api/users HTTP/1.1",
      "Host: example.com",
      "User-Agent: Mozilla/5.0"
    ],
    "body": "",
    "options": {
      "level": 3,
      "risk": 2
    }
  }'
```

**Section sources**
- [app.py](file://src/backEnd/app.py#L36-L42)

## 错误处理指南

### 常见错误状态码
| 状态码 | 含义 | 建议处理方式 |
|--------|------|--------------|
| 200 | 成功 | 正常处理响应数据 |
| 400 | 请求参数错误 | 检查请求参数和请求体格式 |
| 404 | 资源不存在 | 检查URL路径和资源ID |
| 500 | 服务器内部错误 | 检查服务日志，重试请求 |
| 503 | 服务不可用 | 检查数据库连接，稍后重试 |

### 错误响应结构
所有错误响应都遵循统一格式：
```json
{
  "code": 500,
  "success": false,
  "message": "详细的错误信息",
  "data": null
}
```

### 错误处理最佳实践
1. **客户端重试机制**：对于5xx错误，实现指数退避重试机制。
2. **参数验证**：在发送请求前验证所有参数的有效性。
3. **日志记录**：记录所有错误响应，便于调试和问题追踪。
4. **用户友好提示**：将技术性错误信息转换为用户友好的提示。
5. **资源清理**：在请求失败时，清理可能创建的临时资源。

### 特定错误处理
- **数据库连接错误**：检查`header_db`和`current_db`连接状态，确保数据库文件可访问。
- **权限错误**：确保请求来自允许的IP地址（`127.0.0.1`或`localhost`）。
- **文件创建错误**：检查临时文件目录是否存在且可写。
- **规则冲突错误**：检查持久化规则名称是否已存在。

**Section sources**
- [BaseResponseMsg.py](file://src/backEnd/model/BaseResponseMsg.py#L1-L21)
- [taskService.py](file://src/backEnd/service/taskService.py#L24-L37)
- [headerRuleService.py](file://src/backEnd/service/headerRuleService.py#L74-L175)