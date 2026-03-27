# 嵌套加密参数测试注意事项

## ⚠️ 重要警告

### 1. 严禁修改第三方库

**绝对不要**向以下目录写入任何文件：
- `src/backEnd/third_lib/sqlmap/`
- `src/backEnd/third_lib/sqlmap/tamper/`
- `src/backEnd/third_lib/sqlmap/preprocess/`

这是 SQLMap 开源项目的 git 子模块，修改会导致：
- 子模块状态异常
- 无法更新 SQLMap 版本
- 代码提交冲突
- 违反开源协议

### 2. Tamper 脚本的正确位置

#### 方案一：SQLMap 安装目录（推荐临时使用）
```
/path/to/sqlmap/tamper/your_script.py
```

#### 方案二：项目目录（推荐长期维护）
```
sqlmapWebUI/
├── src/
│   ├── backEnd/
│   │   └── tampers/          # 自建目录
│   │       └── base64_nested.py
```

使用时通过 `--tamper` 指定完整路径：
```bash
python sqlmap.py -u URL --tamper=/path/to/project/src/backEnd/tampers/base64_nested.py
```

#### 方案三：当前工作目录
```bash
# 将 tamper 脚本放在执行 sqlmap 的目录
cd /path/to/workspace
python sqlmap.py -u URL --tamper=./base64_nested.py
```

---

## 安全注意事项

### 1. 授权测试

**仅在获得明确授权的情况下进行测试！**

未经授权的测试可能违反：
- 《网络安全法》
- 《刑法》第 285、286 条
- 公司安全政策
- 国际法律法规

### 2. 测试环境隔离

- 使用本地靶场（如 VulnShop）
- 避免在生产环境测试
- 使用虚拟机或容器隔离
- 测试后清理数据

### 3. 数据保护

- 不要泄露真实用户数据
- 敏感信息及时清理
- 测试报告加密存储
- 限制访问权限

---

## 技术注意事项

### 1. 编码问题

```python
# 确保使用正确的编码
def tamper(payload, **kwargs):
    # 错误：可能导致编码错误
    data = json.dumps(inner)
    
    # 正确：指定编码
    data = json.dumps(inner, ensure_ascii=False)
    encoded = base64.b64encode(data.encode('utf-8')).decode('utf-8')
```

### 2. 特殊字符处理

```python
# SQLMap payload 可能包含特殊字符
def tamper(payload, **kwargs):
    # 需要正确处理引号、换行等字符
    inner = {"name": payload.replace("'", "''")}
    # 或根据具体情况转义
```

### 3. 长度限制

Base64 编码会增加约 33% 的长度：
- 原始长度：100 字节
- Base64 后：约 133 字节

如果服务器有长度限制，可能需要：
- 使用更短的注入技术
- 分块传输
- 调整服务器配置（测试环境）

### 4. 时间同步

动态密钥场景下：
```python
import time

def tamper(payload, **kwargs):
    # 确保与服务器时间同步
    # 可能需要从响应中提取时间戳
    timestamp = int(time.time())
    # 或
    timestamp = kwargs.get('headers', {}).get('X-Server-Time')
```

---

## 调试技巧

### 1. 使用代理查看请求

```bash
python sqlmap.py -u URL --data='...' --tamper=script -p param --proxy=http://127.0.0.1:8080
```

在 Burp 中查看实际发送的请求内容。

### 2. 添加调试输出

```python
def tamper(payload, **kwargs):
    import sys
    sys.stderr.write(f"[DEBUG] Original: {payload}\n")
    
    # 处理逻辑
    result = process(payload)
    
    sys.stderr.write(f"[DEBUG] Result: {result}\n")
    return result
```

### 3. 本地测试 Tamper 脚本

```python
# test_tamper.py
import sys
sys.path.insert(0, '/path/to/sqlmap')

from tamper.base64_nested import tamper

# 测试
test_payload = "test' AND 1=1--"
result = tamper(test_payload)
print(f"Input: {test_payload}")
print(f"Output: {result}")

# 验证输出
decoded = base64.b64decode(result)
print(f"Decoded: {decoded}")
```

### 4. Verbose 模式

```bash
# 增加输出详细程度
python sqlmap.py -u URL ... -v 3  # 或 -v 4, -v 5, -v 6
```

---

## 常见问题排查

### Q: SQLMap 报错 "tamper module not found"

**原因**：
- 脚本路径错误
- 脚本语法错误
- 缺少依赖

**解决**：
```bash
# 检查路径
ls -la /path/to/tamper_script.py

# 检查语法
python -m py_compile tamper_script.py

# 使用绝对路径
python sqlmap.py ... --tamper=/absolute/path/to/script.py
```

### Q: Tamper 脚本执行但没有效果

**原因**：
- 脚本逻辑错误
- SQLMap 缓存了旧结果
- 参数名不匹配

**解决**：
```bash
# 清除会话缓存
python sqlmap.py ... --flush-session

# 检查参数名是否正确
python sqlmap.py ... -p content  # 确保是实际的参数名
```

### Q: Base64 解码失败

**原因**：
- 编码错误（URL 安全 Base64 vs 标准 Base64）
- 填充问题
- 字符集问题

**解决**：
```python
import base64

# 标准 Base64
base64.b64encode(data)

# URL 安全 Base64
base64.urlsafe_b64encode(data)

# 处理填充
data += '=' * (4 - len(data) % 4)
```

### Q: SQLMap 检测到注入但无法提取数据

**原因**：
- 响应也是加密的
- 响应格式解析失败
- 盲注技术限制

**解决**：
- 手动验证注入
- 检查响应处理
- 使用 `--technique` 指定注入技术
- 调整 `--time-sec` 时间参数

---

## 最佳实践

### 1. 版本控制

将自定义 tamper 脚本纳入项目版本控制：
```bash
git add src/backEnd/tampers/
git commit -m "Add base64 nested param tamper script"
```

### 2. 文档注释

```python
#!/usr/bin/env python3
"""
Tamper script for XXX encryption

Author: Your Name
Date: 2024-01-01
Version: 1.0

Description:
    Brief description of what this script does

Usage:
    python sqlmap.py -u URL --tamper=this_script.py -p param

Dependencies:
    - pycryptodome (for AES encryption)
    - other dependencies
"""
```

### 3. 模块化设计

```python
# 加密函数独立出来
def encrypt_data(data, key):
    """加密数据"""
    pass

def decrypt_data(data, key):
    """解密数据"""
    pass

def tamper(payload, **kwargs):
    """主入口"""
    inner = {"param": payload}
    encrypted = encrypt_data(json.dumps(inner), KEY)
    return encrypted
```

### 4. 错误处理

```python
def tamper(payload, **kwargs):
    try:
        # 处理逻辑
        return result
    except Exception as e:
        import sys
        sys.stderr.write(f"[Tamper Error] {str(e)}\n")
        # 返回原始 payload，避免中断扫描
        return payload
```

---

## 参考资源

- [SQLMap 官方文档](https://github.com/sqlmapproject/sqlmap/wiki)
- [SQLMap Tamper 脚本集合](https://github.com/sqlmapproject/sqlmap/tree/master/tamper)
- [Base64 编码规范](https://tools.ietf.org/html/rfc4648)
- [OWASP SQL 注入](https://owasp.org/www-community/attacks/SQL_Injection)
