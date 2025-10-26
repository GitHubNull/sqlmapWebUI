# Scope功能验证清单

## 快速验证步骤

### 前置条件
- [ ] 后端服务已启动（默认端口8000）

### 自动化测试

#### 1. 单元测试（必须通过）
```bash
cd e:\devs\python-devs\pycharm-devs\sqlmapWebUI\src\backEnd
python -m pytest tests/test_scope_matcher.py tests/test_header_processor_scope.py -v
```

**预期结果**: ✅ 24/24 测试通过

#### 2. 数据模型测试（必须通过）
```bash
cd e:\devs\python-devs\pycharm-devs\sqlmapWebUI\src\backEnd
python tests/test_scope_crud_simple.py
```

**预期结果**: ✅ 所有数据模型测试通过

#### 3. API端点测试（可选，需要服务运行）
```bash
cd e:\devs\python-devs\pycharm-devs\sqlmapWebUI\src\backEnd
python tests/test_api_endpoints.py
```

**预期结果**: ✅ 所有API请求成功

---

## 手动验证清单

### 任务1: HeaderRuleService传递target_url ✅

**验证文件**: `service/headerRuleService.py`

**检查点**:
- [ ] `preview_header_processing()` 方法签名包含 `target_url` 参数（L545）
- [ ] 调用 `HeaderProcessor.preview_header_processing()` 时传递 `target_url`（L558-559）

**验证方法**: 代码审查

---

### 任务2: API端点处理scope字段CRUD ✅

#### 2.1 创建规则 (Create)

**API**: `POST /commonApi/header/persistent-header-rules`

**检查点**:
- [ ] 接收模型 `PersistentHeaderRuleCreate` 包含 `scope` 字段
- [ ] 序列化scope为JSON存储（`headerRuleService.py` L115-118）
- [ ] **关键**: 响应中返回scope字段（L146）

**验证方法**:
```bash
# 使用Postman或curl测试
curl -X POST http://localhost:8000/commonApi/header/persistent-header-rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "测试规则",
    "header_name": "X-Test",
    "header_value": "Value",
    "priority": 50,
    "scope": {
      "host_pattern": "*.example.com"
    }
  }'
```

**预期响应**:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "scope": {
      "host_pattern": "*.example.com"
    },
    ...
  }
}
```

#### 2.2 获取规则列表 (Read - List)

**API**: `GET /commonApi/header/persistent-header-rules`

**检查点**:
- [ ] SQL查询包含 `scope_config` 字段（L178, L186）
- [ ] **关键**: 解析scope_config并返回（L204-224）
- [ ] 每个规则都包含 `scope` 字段（可以是null或dict）

**验证方法**:
```bash
curl -X GET http://localhost:8000/commonApi/header/persistent-header-rules
```

**预期响应**:
```json
{
  "success": true,
  "data": {
    "rules": [
      {
        "id": 1,
        "name": "规则1",
        "scope": { "host_pattern": "*.example.com" }
      },
      {
        "id": 2,
        "name": "规则2",
        "scope": null
      }
    ]
  }
}
```

#### 2.3 获取单个规则 (Read - Detail)

**API**: `GET /commonApi/header/persistent-header-rules/{rule_id}`

**检查点**:
- [ ] SQL查询包含 `scope_config` 字段（L268）
- [ ] **关键**: 解析scope_config并返回（L279-294）
- [ ] 响应包含 `scope` 字段

**验证方法**:
```bash
curl -X GET http://localhost:8000/commonApi/header/persistent-header-rules/1
```

**预期响应**:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "scope": { "host_pattern": "*.example.com" }
  }
}
```

#### 2.4 更新规则 (Update)

**API**: `PUT /commonApi/header/persistent-header-rules/{rule_id}`

**检查点**:
- [ ] 接收模型 `PersistentHeaderRuleUpdate` 包含 `scope` 字段
- [ ] **关键**: 处理scope字段更新（L397-404）
- [ ] 序列化scope为JSON并更新数据库

**验证方法**:
```bash
curl -X PUT http://localhost:8000/commonApi/header/persistent-header-rules/1 \
  -H "Content-Type: application/json" \
  -d '{
    "scope": {
      "host_pattern": "*.test.com"
    }
  }'
```

**预期响应**:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "scope": { "host_pattern": "*.test.com" }
  }
}
```

#### 2.5 预览功能 (Preview)

**API**: `POST /commonApi/header/header-processing/preview`

**检查点**:
- [ ] 请求模型包含 `target_url` 字段（`headerController.py` L246）
- [ ] 传递 `target_url` 给服务层（L264）
- [ ] 服务层传递给HeaderProcessor（`headerRuleService.py` L558-559）

**验证方法**:
```bash
curl -X POST http://localhost:8000/commonApi/header/header-processing/preview \
  -H "Content-Type: application/json" \
  -d '{
    "headers": ["Content-Type: application/json"],
    "target_url": "https://api.example.com/v1/users"
  }'
```

**预期响应**:
```json
{
  "success": true,
  "data": {
    "original_headers": [...],
    "processed_headers": [...],
    "applied_rules": [...]
  }
}
```

---

## 关键代码位置

### 服务层修改 (`service/headerRuleService.py`)

| 功能 | 行号 | 说明 |
|------|------|------|
| 创建返回scope | L146 | `scope=rule_data.scope.to_dict() if rule_data.scope else None` |
| 列表解析scope | L204-224 | 解析scope_config JSON为字典 |
| 详情解析scope | L279-294 | 解析scope_config JSON为字典 |
| 更新处理scope | L397-404 | 序列化并更新scope_config |
| 预览传递url | L558-559 | 传递target_url参数 |

### API层 (`api/commonApi/headerController.py`)

| 功能 | 行号 | 说明 |
|------|------|------|
| 预览请求模型 | L246 | `target_url: Optional[str]` |
| 预览调用 | L264 | 传递target_url参数 |

---

## 验证结果记录

### 自动化测试
- [ ] 单元测试: __/24 通过
- [ ] 数据模型测试: __/6 通过
- [ ] API端点测试: __/7 通过

### 功能验证
- [ ] 任务1: target_url传递 ✅/❌
- [ ] 任务2.1: 创建规则返回scope ✅/❌
- [ ] 任务2.2: 列表返回scope ✅/❌
- [ ] 任务2.3: 详情返回scope ✅/❌
- [ ] 任务2.4: 更新scope ✅/❌
- [ ] 任务2.5: 预览传递url ✅/❌

### 向后兼容性
- [ ] 不带scope的规则正常工作 ✅/❌
- [ ] 现有规则不受影响 ✅/❌
- [ ] 数据库自动迁移 ✅/❌

---

## 问题记录

如有问题，请在此记录：

| 序号 | 问题描述 | 影响范围 | 解决方案 | 状态 |
|------|---------|---------|---------|------|
| 1 | - | - | - | - |

---

**验证人**: _____________
**验证时间**: _____________
**验证结果**: ✅通过 / ❌未通过

---

## 快速参考

### 启动后端服务
```bash
cd e:\devs\python-devs\pycharm-devs\sqlmapWebUI\src\backEnd
python main.py
# 或
python app.py
```

### 查看数据库
```bash
cd e:\devs\python-devs\pycharm-devs\sqlmapWebUI\src\backEnd
sqlite3 headers.db
.schema persistent_header_rules
SELECT * FROM persistent_header_rules;
```

### 测试工具
- Postman
- curl
- Python requests库
- 浏览器开发者工具

---

**最后更新**: 2025-10-26
