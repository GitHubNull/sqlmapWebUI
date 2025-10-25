# Mock 数据生成器使用指南

## 📦 已安装的依赖

- **mockjs**: 开源免费的前端数据模拟库
- **@types/mockjs**: TypeScript 类型定义

## 🎯 功能特性

### 1. 四种数据生成模式

```typescript
import { MockDataMode } from '@/utils/mockData'

// 模式选项：
MockDataMode.NORMAL      // 普通模式 - 正常长度的URL和主机名
MockDataMode.LONG_URL    // 超长URL模式 - 多级路径 + 大量查询参数
MockDataMode.LONG_HOST   // 超长主机名模式 - 5-8级子域名
MockDataMode.MIXED       // 混合模式 - 50%普通 + 25%超长主机 + 25%超长URL
```

### 2. 数据示例

#### 普通模式 (NORMAL)
```
主机: example.com
URL: https://example.com/api/users?id=123
```

#### 超长URL模式 (LONG_URL)
```
主机: example.com
URL: https://example.com/resource/category/subcategory/item/detail/view/page/section?
     param1=abcdefghij&param2=klmnopqrst&param3=uvwxyzabcd&...（15-25个参数）
```

#### 超长主机名模式 (LONG_HOST)
```
主机: api-development.backend-staging.service-production.data-secure.cdn-static.media-assets.example.com
URL: https://api-development.backend-staging...example.com/api/users?id=123
```

## 🔧 配置方法

### 在 `task.ts` 中修改配置

```typescript
// src/frontEnd/src/api/task.ts

// 开关：是否使用Mock数据
const USE_MOCK_DATA = true  // 改为 false 恢复真实API

// Mock数据配置
const MOCK_CONFIG = {
  count: 200,                    // 修改数据数量
  mode: MockDataMode.MIXED,      // 修改数据模式
  delay: 800,                    // 修改网络延迟（毫秒）
}
```

### 测试场景建议

| 测试目的 | 推荐配置 |
|---------|---------|
| 测试超长URL显示 | `mode: MockDataMode.LONG_URL, count: 50` |
| 测试超长主机名显示 | `mode: MockDataMode.LONG_HOST, count: 50` |
| 综合测试 | `mode: MockDataMode.MIXED, count: 200` |
| 压力测试 | `mode: MockDataMode.MIXED, count: 500+` |

## 📊 数据结构

生成的每条数据包含：

```typescript
{
  engineid: number,        // 引擎ID（1000+索引）
  taskid: string,          // 任务ID（使用Mock.js的@guid）
  scanUrl: string,         // 扫描URL（根据模式生成）
  host: string,            // 主机名（根据模式生成）
  status: TaskStatus,      // 随机状态
  createTime: string,      // 随机时间（ISO格式）
  headers: string[],       // 随机请求头
  body: string,            // 随机请求体
  options: {...},          // 随机选项
  updateTime: string,      // 更新时间
}
```

## 🎲 Mock.js 使用示例

```typescript
// 生成超长URL的核心代码
function generateLongUrl(host: string): string {
  // 5-10级路径
  const pathLevels = Mock.Random.integer(5, 10)
  const pathParts: string[] = []
  
  for (let i = 0; i < pathLevels; i++) {
    pathParts.push(Mock.Random.word(5, 15))
  }
  
  // 15-25个查询参数
  const paramCount = Mock.Random.integer(15, 25)
  const params: string[] = []
  
  for (let i = 0; i < paramCount; i++) {
    const key = Mock.Random.word(5, 12)
    const value = Mock.Random.string('lower', 10, 30)
    params.push(`${key}=${value}`)
  }
  
  return `https://${host}/${pathParts.join('/')}?${params.join('&')}`
}
```

## ✅ 使用流程

1. **确认Mock模式已开启**
   ```typescript
   // src/frontEnd/src/api/task.ts
   const USE_MOCK_DATA = true
   ```

2. **选择测试模式**
   ```typescript
   const MOCK_CONFIG = {
     count: 200,
     mode: MockDataMode.LONG_URL,  // 测试超长URL
   }
   ```

3. **启动前端服务**
   ```bash
   cd src/frontEnd
   pnpm dev
   ```

4. **查看控制台输出**
   ```
   🔄 使用Mock数据模式
   📊 配置: 200条数据, 模式=long_url
   🎲 Mock数据生成模式: long_url
   📊 生成数量: 200 条
   ✅ Mock数据生成完成！
   ```

5. **验证页面显示**
   - 检查超长URL是否正常显示
   - 检查是否有文字溢出或遮挡
   - 测试分页功能
   - 测试滚动功能

## 🔄 恢复真实API

测试完成后，修改配置即可：

```typescript
// src/frontEnd/src/api/task.ts
const USE_MOCK_DATA = false  // 关闭Mock数据
```

## 💡 提示

- 混合模式能覆盖更多边界情况
- 建议先用小数据量（50条）测试，确认显示正常后再增加
- Mock.js 还支持更多随机数据类型，可查阅官方文档扩展
- 生成的数据会在控制台显示详细的分类统计
