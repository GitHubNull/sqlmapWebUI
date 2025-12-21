<template>
  <div class="results-wrapper">
    <div v-if="loadingPayload" class="loading-small">
      <ProgressSpinner style="width: 30px; height: 30px" />
    </div>
    <div v-else-if="hasValidData" class="results-container">
      <!-- 目标信息卡片 -->
      <div v-if="targetInfo" class="target-card">
        <div class="card-header">
          <i class="pi pi-bullseye"></i>
          <span>扫描目标</span>
        </div>
        <div class="card-body">
          <div class="target-info-grid">
            <div v-if="targetInfo.url" class="info-item">
              <label>目标URL</label>
              <div class="value-with-copy">
                <span class="value url-value">{{ targetInfo.url }}</span>
                <Button icon="pi pi-copy" text size="small" @click="copyText(targetInfo.url, '目标URL')" title="复制URL" />
              </div>
            </div>
            <div v-if="targetInfo.query" class="info-item">
              <label>查询参数</label>
              <div class="value-with-copy">
                <code class="value param-value">{{ targetInfo.query }}</code>
                <Button icon="pi pi-copy" text size="small" @click="copyText(targetInfo.query, '查询参数')" title="复制参数" />
              </div>
            </div>
            <div v-if="targetInfo.data" class="info-item">
              <label>POST数据</label>
              <div class="value-with-copy">
                <code class="value param-value">{{ targetInfo.data }}</code>
                <Button icon="pi pi-copy" text size="small" @click="copyText(targetInfo.data, 'POST数据')" title="复制数据" />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 注入点列表 -->
      <div v-if="hasVulnerability" class="injection-section">
        <div class="section-header">
          <i class="pi pi-exclamation-triangle"></i>
          <span>发现 {{ injectionPoints.length }} 个注入点</span>
          <Tag severity="danger" class="vuln-tag">存在SQL注入漏洞</Tag>
        </div>

        <div class="injection-cards">
          <div v-for="(point, idx) in injectionPoints" :key="idx" class="injection-card">
            <div class="card-header">
              <div class="header-left">
                <Tag :severity="getPlaceSeverity(point.place)" class="place-tag">{{ point.place || 'UNKNOWN' }}</Tag>
                <span class="param-name">参数: <strong>{{ point.parameter || 'unknown' }}</strong></span>
              </div>
              <div class="header-right">
                <Tag v-if="point.dbms" severity="info" icon="pi pi-database">{{ point.dbms }} {{ formatDbmsVersion(point.dbms_version) }}</Tag>
              </div>
            </div>

            <div class="card-body">
              <!-- 注入技术列表 -->
              <div v-if="hasValidTechniques(point)" class="techniques-section">
                <div class="techniques-header">
                  <span>检测到的注入技术 ({{ getTechniqueCount(point) }} 种)</span>
                </div>
                <div class="techniques-list">
                  <div v-for="(technique, techKey) in point.data" :key="techKey" class="technique-item">
                    <div class="technique-header">
                      <Tag severity="warning" class="tech-type-tag">{{ getTechniqueType(techKey) }}</Tag>
                      <span class="technique-title">{{ technique.title || '未知技术' }}</span>
                    </div>
                    <div class="technique-details">
                      <!-- Payload -->
                      <div v-if="technique.payload" class="detail-row payload-row">
                        <label>Payload:</label>
                        <div class="payload-container">
                          <code class="payload-code">{{ technique.payload }}</code>
                          <Button 
                            icon="pi pi-copy" 
                            text 
                            size="small" 
                            @click="copyText(technique.payload, 'Payload')" 
                            title="复制Payload" 
                            class="copy-btn"
                          />
                        </div>
                      </div>
                      <!-- Vector -->
                      <div v-if="technique.vector" class="detail-row">
                        <label>Vector:</label>
                        <code class="detail-value">{{ technique.vector }}</code>
                      </div>
                      <!-- Response Codes -->
                      <div v-if="technique.trueCode !== undefined || technique.falseCode !== undefined" class="detail-row codes-row">
                        <label>响应码:</label>
                        <div class="codes-container">
                          <Tag v-if="technique.trueCode !== undefined" severity="success" class="code-tag">True: {{ technique.trueCode }}</Tag>
                          <Tag v-if="technique.falseCode !== undefined" severity="danger" class="code-tag">False: {{ technique.falseCode }}</Tag>
                        </div>
                      </div>
                      <!-- Prefix/Suffix -->
                      <div v-if="point.prefix || point.suffix" class="detail-row">
                        <label>Prefix/Suffix:</label>
                        <span class="detail-value">
                          <code v-if="point.prefix">'{{ point.prefix }}'</code>
                          <span v-if="point.prefix && point.suffix"> / </span>
                          <code v-if="point.suffix">'{{ point.suffix }}'</code>
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div v-else class="no-techniques">
                <i class="pi pi-info-circle"></i>
                <span>未检测到具体注入技术详情</span>
              </div>

              <!-- 复制完整验证命令 -->
              <div v-if="hasValidTechniques(point)" class="action-section">
                <Button 
                  label="复制验证Payload" 
                  icon="pi pi-copy" 
                  severity="secondary" 
                  size="small"
                  @click="copyAllPayloads(point)"
                />
                <Button 
                  v-if="targetInfo?.url"
                  label="复制完整验证URL" 
                  icon="pi pi-external-link" 
                  severity="info" 
                  size="small"
                  @click="copyVerificationUrl(point)"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 其他扫描数据（如DBMS信息、用户信息等） -->
      <div v-if="otherScanData.length > 0" class="other-data-section">
        <div class="section-header">
          <i class="pi pi-database"></i>
          <span>扫描获取的数据 ({{ otherScanData.length }} 项)</span>
        </div>
        <div class="other-data-cards">
          <div v-for="(item, idx) in otherScanData" :key="idx" class="other-data-card">
            <div class="card-header">
              <i :class="item.icon"></i>
              <span>{{ item.label }}</span>
              <Tag severity="secondary" class="type-tag">{{ item.contentType }}</Tag>
            </div>
            <div class="card-body">
              <pre class="data-content">{{ formatOtherDataValue(item) }}</pre>
              <Button 
                icon="pi pi-copy" 
                text 
                size="small" 
                @click="copyText(formatOtherDataValue(item), item.label)" 
                title="复制内容" 
                class="copy-btn"
              />
            </div>
          </div>
        </div>
      </div>

      <!-- 无注入点且无其他数据时显示原始数据 -->
      <div v-if="!hasVulnerability && otherScanData.length === 0 && payloadData && payloadData.length > 0" class="raw-data-section">
        <div class="section-header">
          <i class="pi pi-info-circle"></i>
          <span>扫描数据</span>
        </div>
        <DataTable :value="payloadData" stripedRows class="result-table" scrollable scrollHeight="300px">
          <Column field="index" header="序号" style="width: 80px" />
          <Column field="status" header="状态" style="width: 100px">
            <template #body="{ data }">
              {{ data.status ?? '-' }}
            </template>
          </Column>
          <Column header="类型" style="width: 150px">
            <template #body="{ data }">
              {{ data.contentType || data.content_type || '-' }}
            </template>
          </Column>
          <Column field="value" header="内容">
            <template #body="{ data }">
              <div class="raw-value">{{ formatRawValue(data.value) }}</div>
            </template>
          </Column>
        </DataTable>
      </div>
    </div>
    
    <!-- 无数据状态 -->
    <div v-else class="empty-state">
      <i class="pi pi-check-circle empty-icon"></i>
      <span class="empty-text">未发现SQL注入漏洞</span>
      <span class="empty-subtext">扫描已完成，目标参数未检测到注入点</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useToast } from 'primevue/usetoast'

// ==================== 类型定义 ====================
interface Props {
  payloadData: any[] | null | undefined
  loadingPayload: boolean
}

// 目标信息接口
interface TargetInfo {
  url?: string
  query?: string
  data?: string
}

// 注入技术详情接口
interface TechniqueDetail {
  title?: string
  payload?: string
  vector?: string
  trueCode?: number
  falseCode?: number
  where?: number
  comment?: string
  templatePayload?: string | null
  matchRatio?: number | null
}

// 注入点接口
interface InjectionPoint {
  place?: string
  parameter?: string
  ptype?: number
  prefix?: string
  suffix?: string
  clause?: number[]
  notes?: string[]
  data?: Record<string, TechniqueDetail>
  conf?: Record<string, any>
  dbms?: string
  dbms_version?: string[]
  os?: string | null
}

// 其他扫描数据接口
interface OtherScanData {
  contentType: string
  label: string
  icon: string
  value: any
  rawValue: string
}

const props = defineProps<Props>()
const toast = useToast()

// ==================== 安全解析辅助函数 ====================

/**
 * 安全解析JSON字符串
 */
function safeParseJson<T>(jsonStr: string | null | undefined, defaultValue: T): T {
  if (!jsonStr || typeof jsonStr !== 'string' || jsonStr.trim() === '') {
    return defaultValue
  }
  try {
    const result = JSON.parse(jsonStr)
    return result ?? defaultValue
  } catch {
    return defaultValue
  }
}

/**
 * 安全获取字符串值
 */
function safeString(value: any, defaultValue: string = ''): string {
  if (value === null || value === undefined) return defaultValue
  return String(value)
}

/**
 * 安全获取数组
 */
function safeArray<T>(value: any, defaultValue: T[] = []): T[] {
  if (!value || !Array.isArray(value)) return defaultValue
  return value
}

/**
 * 安全获取对象
 */
function safeObject<T extends object>(value: any, defaultValue: T): T {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return defaultValue
  return value as T
}

// ==================== 数据解析计算属性 ====================

/**
 * 解析目标信息（增强鲁棒性）
 */
const targetInfo = computed<TargetInfo | null>(() => {
  if (!props.payloadData || !Array.isArray(props.payloadData)) return null
  
  const targetItem = props.payloadData.find(item => 
    item && (item.contentType === 'TARGET' || item.content_type === 'TARGET')
  )
  if (!targetItem) return null
  
  const parsed = safeParseJson<TargetInfo | null>(targetItem.value, null)
  if (!parsed) return null
  
  // 确保至少有url字段
  return {
    url: safeString(parsed.url),
    query: parsed.query ? safeString(parsed.query) : undefined,
    data: parsed.data ? safeString(parsed.data) : undefined
  }
})

/**
 * 解析注入点信息（增强鲁棒性）
 */
const injectionPoints = computed<InjectionPoint[]>(() => {
  if (!props.payloadData || !Array.isArray(props.payloadData)) return []
  
  const techItem = props.payloadData.find(item => 
    item && (item.contentType === 'TECHNIQUES' || item.content_type === 'TECHNIQUES')
  )
  if (!techItem) return []
  
  const techniques = safeParseJson<any[]>(techItem.value, [])
  if (!Array.isArray(techniques)) return []
  
  // 过滤并规范化每个注入点
  return techniques
    .filter(point => point && typeof point === 'object')
    .map(point => ({
      place: safeString(point.place, 'UNKNOWN'),
      parameter: safeString(point.parameter, 'unknown'),
      ptype: point.ptype ?? 0,
      prefix: safeString(point.prefix),
      suffix: safeString(point.suffix),
      clause: safeArray<number>(point.clause),
      notes: safeArray<string>(point.notes),
      data: normalizeDataObject(point.data),
      conf: safeObject(point.conf, {}),
      dbms: safeString(point.dbms),
      dbms_version: safeArray<string>(point.dbms_version),
      os: point.os ?? null
    }))
})

/**
 * 规范化注入技术data对象
 */
function normalizeDataObject(data: any): Record<string, TechniqueDetail> {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return {}
  }
  
  const result: Record<string, TechniqueDetail> = {}
  for (const [key, value] of Object.entries(data)) {
    if (value && typeof value === 'object') {
      const tech = value as any
      result[key] = {
        title: safeString(tech.title, '未知技术'),
        payload: safeString(tech.payload, ''),
        vector: tech.vector ? safeString(tech.vector) : undefined,
        trueCode: typeof tech.trueCode === 'number' ? tech.trueCode : undefined,
        falseCode: typeof tech.falseCode === 'number' ? tech.falseCode : undefined,
        where: tech.where,
        comment: tech.comment,
        templatePayload: tech.templatePayload,
        matchRatio: tech.matchRatio
      }
    }
  }
  return result
}

/**
 * 解析其他扫描数据（DBMS_FINGERPRINT, BANNER, CURRENT_USER等）
 */
const otherScanData = computed<OtherScanData[]>(() => {
  if (!props.payloadData || !Array.isArray(props.payloadData)) return []
  
  // 需要特殊处理的类型
  const specialTypes = ['TARGET', 'TECHNIQUES']
  
  // 类型标签映射
  const typeLabels: Record<string, { label: string; icon: string }> = {
    'DBMS_FINGERPRINT': { label: '数据库指纹', icon: 'pi pi-server' },
    'BANNER': { label: '数据库横幅', icon: 'pi pi-info-circle' },
    'CURRENT_USER': { label: '当前用户', icon: 'pi pi-user' },
    'CURRENT_DB': { label: '当前数据库', icon: 'pi pi-database' },
    'HOSTNAME': { label: '主机名', icon: 'pi pi-desktop' },
    'IS_DBA': { label: 'DBA权限', icon: 'pi pi-shield' },
    'USERS': { label: '用户列表', icon: 'pi pi-users' },
    'PASSWORDS': { label: '密码信息', icon: 'pi pi-key' },
    'PRIVILEGES': { label: '权限信息', icon: 'pi pi-lock' },
    'ROLES': { label: '角色信息', icon: 'pi pi-id-card' },
    'DBS': { label: '数据库列表', icon: 'pi pi-folder' },
    'TABLES': { label: '表列表', icon: 'pi pi-table' },
    'COLUMNS': { label: '列列表', icon: 'pi pi-list' },
    'SCHEMA': { label: '数据库架构', icon: 'pi pi-sitemap' },
    'COUNT': { label: '记录数量', icon: 'pi pi-chart-bar' },
    'DUMP_TABLE': { label: '表数据', icon: 'pi pi-download' },
    'SEARCH': { label: '搜索结果', icon: 'pi pi-search' },
    'SQL_QUERY': { label: 'SQL查询结果', icon: 'pi pi-code' },
    'FILE_READ': { label: '文件读取', icon: 'pi pi-file' },
    'FILE_WRITE': { label: '文件写入', icon: 'pi pi-file-edit' },
    'OS_CMD': { label: '系统命令', icon: 'pi pi-cog' }
  }
  
  return props.payloadData
    .filter(item => {
      if (!item) return false
      const type = item.contentType || item.content_type
      return type && !specialTypes.includes(type)
    })
    .map(item => {
      const type = item.contentType || item.content_type || 'UNKNOWN'
      const typeInfo = typeLabels[type] || { label: type, icon: 'pi pi-file' }
      const parsed = safeParseJson(item.value, null)
      
      return {
        contentType: type,
        label: typeInfo.label,
        icon: typeInfo.icon,
        value: parsed,
        rawValue: safeString(item.value)
      }
    })
})

/**
 * 是否有有效数据
 */
const hasValidData = computed(() => {
  return targetInfo.value !== null || 
         injectionPoints.value.length > 0 || 
         otherScanData.value.length > 0 ||
         (props.payloadData && Array.isArray(props.payloadData) && props.payloadData.length > 0)
})

/**
 * 是否有注入漏洞
 */
const hasVulnerability = computed(() => {
  return injectionPoints.value.length > 0 && 
         injectionPoints.value.some(p => p.data && Object.keys(p.data).length > 0)
})

// ==================== 辅助函数 ====================

/**
 * 获取位置标签颜色
 */
function getPlaceSeverity(place: string | undefined): string {
  if (!place) return 'secondary'
  const map: Record<string, string> = {
    'GET': 'info',
    'POST': 'warning',
    'COOKIE': 'danger',
    'HEADER': 'secondary',
    'URI': 'contrast'
  }
  return map[place.toUpperCase()] || 'secondary'
}

/**
 * 获取注入技术类型名称
 */
function getTechniqueType(key: string): string {
  const typeMap: Record<string, string> = {
    '1': 'Boolean盲注',
    '2': '报错注入',
    '3': 'UNION注入',
    '4': '堆叠查询',
    '5': '时间盲注',
    '6': '内联查询'
  }
  return typeMap[key] || `类型${key}`
}

/**
 * 格式化数据库版本
 */
function formatDbmsVersion(version: string[] | undefined): string {
  if (!version || !Array.isArray(version) || version.length === 0) return ''
  return version.filter(v => v).join(', ')
}

/**
 * 格式化原始值（用于显示）
 */
function formatRawValue(value: string | null | undefined): string {
  if (!value) return '-'
  try {
    const parsed = JSON.parse(value)
    if (typeof parsed === 'string') return parsed
    return JSON.stringify(parsed, null, 2)
  } catch {
    const str = String(value)
    return str.length > 500 ? str.substring(0, 500) + '...' : str
  }
}

/**
 * 格式化其他扫描数据的值
 */
function formatOtherDataValue(data: OtherScanData): string {
  if (data.value !== null && data.value !== undefined) {
    if (typeof data.value === 'string') return data.value
    if (Array.isArray(data.value)) return data.value.join(', ')
    if (typeof data.value === 'object') return JSON.stringify(data.value, null, 2)
    return String(data.value)
  }
  return formatRawValue(data.rawValue)
}

/**
 * 检查注入点是否有有效数据
 */
function hasValidTechniques(point: InjectionPoint): boolean {
  return point.data !== undefined && 
         Object.keys(point.data).length > 0 &&
         Object.values(point.data).some(t => t.payload)
}

/**
 * 获取技术数量
 */
function getTechniqueCount(point: InjectionPoint): number {
  if (!point.data) return 0
  return Object.keys(point.data).length
}

// ==================== 复制功能 ====================

/**
 * 复制文本到剪贴板
 */
function copyText(text: string | undefined, label: string) {
  if (!text) {
    toast.add({ severity: 'warn', summary: '无内容', detail: '没有可复制的内容', life: 2000 })
    return
  }
  navigator.clipboard.writeText(text).then(() => {
    toast.add({ severity: 'success', summary: '复制成功', detail: `${label}已复制到剪贴板`, life: 2000 })
  }).catch(() => {
    toast.add({ severity: 'error', summary: '复制失败', detail: '无法访问剪贴板', life: 2000 })
  })
}

/**
 * 复制所有Payload
 */
function copyAllPayloads(point: InjectionPoint) {
  if (!point.data || Object.keys(point.data).length === 0) {
    toast.add({ severity: 'warn', summary: '无Payload', detail: '没有可复制的Payload', life: 2000 })
    return
  }
  
  const payloads = Object.values(point.data)
    .filter(tech => tech.payload)
    .map(tech => `# ${tech.title || '未知技术'}\n${tech.payload}`)
    .join('\n\n')
  
  if (!payloads) {
    toast.add({ severity: 'warn', summary: '无Payload', detail: '没有可复制的Payload', life: 2000 })
    return
  }
  
  copyText(payloads, '所有Payload')
}

/**
 * 复制验证URL
 */
function copyVerificationUrl(point: InjectionPoint) {
  if (!targetInfo.value?.url) {
    toast.add({ severity: 'warn', summary: '无目标URL', detail: '无法生成验证URL', life: 2000 })
    return
  }
  
  if (!point.data || Object.keys(point.data).length === 0) {
    toast.add({ severity: 'warn', summary: '无Payload', detail: '没有可用的Payload', life: 2000 })
    return
  }
  
  const firstPayload = Object.values(point.data).find(t => t.payload)
  if (!firstPayload?.payload) {
    toast.add({ severity: 'warn', summary: '无Payload', detail: '没有可用的Payload', life: 2000 })
    return
  }
  
  const baseUrl = targetInfo.value.url
  const param = point.parameter || 'unknown'
  const place = point.place || 'UNKNOWN'
  
  let verifyInfo = `目标URL: ${baseUrl}\n`
  verifyInfo += `注入位置: ${place}\n`
  verifyInfo += `参数名: ${param}\n`
  verifyInfo += `\nPayload: ${firstPayload.payload}\n`
  
  if (place === 'GET' && targetInfo.value.query) {
    verifyInfo += `\n完整URL: ${baseUrl}?${firstPayload.payload}`
  }
  
  copyText(verifyInfo, '验证信息')
}
</script>

<style scoped lang="scss">
.results-wrapper {
  height: 100%;
  overflow: auto;
}

.results-container {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 4px;
}

.loading-small {
  display: flex;
  justify-content: center;
  padding: 40px;
}

// 目标信息卡片
.target-card {
  background: linear-gradient(135deg, rgba(59, 130, 246, 0.08) 0%, rgba(99, 102, 241, 0.05) 100%);
  border: 1px solid rgba(59, 130, 246, 0.2);
  border-radius: 12px;
  overflow: hidden;

  .card-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    background: rgba(59, 130, 246, 0.1);
    border-bottom: 1px solid rgba(59, 130, 246, 0.15);
    font-weight: 600;
    color: #1e40af;

    i { font-size: 16px; }
  }

  .card-body {
    padding: 16px;
  }
}

.target-info-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;

  .info-item {
    display: flex;
    flex-direction: column;
    gap: 4px;

    label {
      font-size: 12px;
      color: #6b7280;
      font-weight: 500;
    }

    .value-with-copy {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .value {
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 13px;
      color: #1f2937;
      word-break: break-all;
    }

    .url-value {
      color: #2563eb;
    }

    .param-value {
      background: rgba(0, 0, 0, 0.05);
      padding: 4px 8px;
      border-radius: 4px;
    }
  }
}

// 注入点区域
.injection-section {
  .section-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 0;
    font-weight: 600;
    color: #dc2626;
    font-size: 15px;

    i { font-size: 18px; }
    
    .vuln-tag {
      margin-left: auto;
    }
  }
}

.injection-cards {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.injection-card {
  background: #fff;
  border: 1px solid rgba(220, 38, 38, 0.2);
  border-radius: 12px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(220, 38, 38, 0.08);

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    background: linear-gradient(135deg, rgba(220, 38, 38, 0.08) 0%, rgba(251, 146, 60, 0.05) 100%);
    border-bottom: 1px solid rgba(220, 38, 38, 0.15);

    .header-left {
      display: flex;
      align-items: center;
      gap: 12px;

      .param-name {
        font-size: 14px;
        color: #374151;
      }
    }
  }

  .card-body {
    padding: 16px;
  }
}

// 注入技术列表
.techniques-section {
  .techniques-header {
    font-size: 13px;
    font-weight: 600;
    color: #4b5563;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px dashed #e5e7eb;
  }
}

.techniques-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.technique-item {
  background: rgba(251, 191, 36, 0.05);
  border: 1px solid rgba(251, 191, 36, 0.2);
  border-radius: 8px;
  padding: 12px;

  .technique-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;

    .technique-title {
      font-size: 13px;
      font-weight: 500;
      color: #374151;
    }
  }

  .technique-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .detail-row {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 12px;

    label {
      color: #6b7280;
      min-width: 70px;
      flex-shrink: 0;
    }

    .detail-value {
      color: #374151;
    }
  }

  .payload-row {
    .payload-container {
      display: flex;
      align-items: center;
      gap: 8px;
      flex: 1;
      background: rgba(0, 0, 0, 0.03);
      padding: 6px 10px;
      border-radius: 6px;
      border: 1px solid rgba(0, 0, 0, 0.08);

      .payload-code {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        color: #dc2626;
        word-break: break-all;
        flex: 1;
      }

      .copy-btn {
        flex-shrink: 0;
      }
    }
  }

  .codes-row {
    .codes-container {
      display: flex;
      gap: 8px;
    }

    .code-tag {
      font-size: 11px;
    }
  }
}

// 操作区域
.action-section {
  display: flex;
  gap: 10px;
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px dashed #e5e7eb;
}

// 无技术详情提示
.no-techniques {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px;
  background: rgba(156, 163, 175, 0.1);
  border-radius: 8px;
  color: #6b7280;
  font-size: 13px;

  i { font-size: 16px; }
}

// 其他扫描数据区域
.other-data-section {
  .section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 0;
    font-weight: 600;
    color: #059669;
    font-size: 15px;

    i { font-size: 18px; }
  }
}

.other-data-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 12px;
}

.other-data-card {
  background: linear-gradient(135deg, rgba(5, 150, 105, 0.08) 0%, rgba(16, 185, 129, 0.05) 100%);
  border: 1px solid rgba(5, 150, 105, 0.2);
  border-radius: 10px;
  overflow: hidden;

  .card-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    background: rgba(5, 150, 105, 0.1);
    border-bottom: 1px solid rgba(5, 150, 105, 0.15);
    font-weight: 500;
    font-size: 13px;
    color: #047857;

    i { font-size: 14px; }

    .type-tag {
      margin-left: auto;
      font-size: 10px;
    }
  }

  .card-body {
    padding: 12px 14px;
    position: relative;

    .data-content {
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 12px;
      color: #374151;
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 150px;
      overflow: auto;
      background: rgba(0, 0, 0, 0.02);
      padding: 8px;
      border-radius: 6px;
    }

    .copy-btn {
      position: absolute;
      top: 8px;
      right: 8px;
    }
  }
}

// 原始数据区域
.raw-data-section {
  .section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 0;
    font-weight: 600;
    color: #4b5563;

    i { font-size: 16px; }
  }

  .raw-value {
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow: auto;
  }
}

// 空状态
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  text-align: center;

  .empty-icon {
    font-size: 48px;
    color: #22c55e;
    margin-bottom: 16px;
  }

  .empty-text {
    font-size: 16px;
    font-weight: 600;
    color: #22c55e;
    margin-bottom: 8px;
  }

  .empty-subtext {
    font-size: 13px;
    color: #9ca3af;
  }
}

// DataTable样式增强
:deep(.result-table) {
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(99, 102, 241, 0.1);

  .p-datatable-thead > tr > th {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
    color: #1f2937;
    font-weight: 600;
  }

  .p-datatable-tbody > tr:hover {
    background: rgba(99, 102, 241, 0.05);
  }
}

// 暗色主题适配
:root[data-theme='dark'] {
  .target-card {
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
    border-color: rgba(59, 130, 246, 0.3);

    .card-header {
      background: rgba(59, 130, 246, 0.2);
      color: #93c5fd;
    }
  }

  .target-info-grid .info-item {
    .value { color: #e5e7eb; }
    .url-value { color: #60a5fa; }
    .param-value { background: rgba(255, 255, 255, 0.1); }
  }

  .injection-card {
    background: #1f2937;
    border-color: rgba(220, 38, 38, 0.3);

    .card-header {
      background: linear-gradient(135deg, rgba(220, 38, 38, 0.15) 0%, rgba(251, 146, 60, 0.1) 100%);
    }
  }

  .technique-item {
    background: rgba(251, 191, 36, 0.1);
    border-color: rgba(251, 191, 36, 0.3);

    .technique-title { color: #e5e7eb; }
    .detail-row .detail-value { color: #d1d5db; }
    
    .payload-row .payload-container {
      background: rgba(0, 0, 0, 0.2);
      border-color: rgba(255, 255, 255, 0.1);
    }
  }

  .no-techniques {
    background: rgba(107, 114, 128, 0.2);
    color: #9ca3af;
  }

  .other-data-card {
    background: linear-gradient(135deg, rgba(5, 150, 105, 0.15) 0%, rgba(16, 185, 129, 0.1) 100%);
    border-color: rgba(5, 150, 105, 0.3);

    .card-header {
      background: rgba(5, 150, 105, 0.2);
      color: #6ee7b7;
    }

    .card-body .data-content {
      color: #d1d5db;
      background: rgba(0, 0, 0, 0.2);
    }
  }

  .empty-state {
    .empty-subtext { color: #6b7280; }
  }

  .raw-data-section .raw-value {
    color: #d1d5db;
  }
}
</style>