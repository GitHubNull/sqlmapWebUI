<template>
  <div class="http-code-editor" :class="{ 'show-search': showSearch }">
    <!-- 搜索工具栏 -->
    <div class="search-toolbar" v-if="showSearch">
      <div class="search-input-group">
        <InputText 
          v-model="searchQuery" 
          :placeholder="searchPlaceholder"
          class="search-input"
          @keyup.enter="findNext"
          @keyup.escape="closeSearch"
          ref="searchInputRef"
        />
        <span class="match-count" v-if="searchQuery && matchInfo">
          {{ matchInfo }}
        </span>
      </div>
      <div class="search-options">
        <Button 
          icon="pi pi-chevron-up" 
          severity="secondary" 
          text 
          size="small" 
          @click="findPrev"
          v-tooltip.top="'上一个 (Shift+F3)'"
          :disabled="!searchQuery"
        />
        <Button 
          icon="pi pi-chevron-down" 
          severity="secondary" 
          text 
          size="small" 
          @click="findNext"
          v-tooltip.top="'下一个 (F3)'"
          :disabled="!searchQuery"
        />
        <span class="separator">|</span>
        <ToggleButton 
          v-model="useRegex" 
          onLabel="正则" 
          offLabel="正则"
          onIcon="pi pi-check"
          offIcon=""
          class="option-toggle"
          v-tooltip.top="'正则表达式'"
        />
        <ToggleButton 
          v-model="caseSensitive" 
          onLabel="Aa" 
          offLabel="Aa"
          onIcon="pi pi-check"
          offIcon=""
          class="option-toggle"
          v-tooltip.top="'大小写敏感'"
        />
        <ToggleButton 
          v-model="invertSearch" 
          onLabel="反转" 
          offLabel="反转"
          onIcon="pi pi-check"
          offIcon=""
          class="option-toggle"
          v-tooltip.top="'反转匹配（高亮不匹配的行）'"
        />
        <span class="separator">|</span>
        <Button 
          icon="pi pi-times" 
          severity="secondary" 
          text 
          size="small" 
          @click="closeSearch"
          v-tooltip.top="'关闭搜索 (Esc)'"
        />
      </div>
    </div>
    
    <!-- 编辑器容器 -->
    <div class="editor-wrapper">
      <div ref="editorContainer" class="editor-container"></div>
      
      <!-- 快捷操作栏 -->
      <div class="editor-actions">
        <Button 
          icon="pi pi-search" 
          severity="secondary" 
          text 
          size="small" 
          @click="toggleSearch"
          v-tooltip.top="'搜索 (Ctrl+F)'"
        />
        <Button 
          icon="pi pi-copy" 
          severity="secondary" 
          text 
          size="small" 
          @click="copyContent"
          v-tooltip.top="'复制全部'"
        />
        <Button 
          icon="pi pi-trash" 
          severity="secondary" 
          text 
          size="small" 
          @click="clearContent"
          v-tooltip.top="'清空'"
          :disabled="!modelValue"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted, nextTick, computed } from 'vue'
import { EditorView, lineNumbers, highlightActiveLine, highlightActiveLineGutter, keymap } from '@codemirror/view'
import { EditorState, Compartment } from '@codemirror/state'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { searchKeymap, highlightSelectionMatches, SearchQuery, findNext as cmFindNext, findPrevious as cmFindPrev, setSearchQuery } from '@codemirror/search'
import { StreamLanguage, HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'

import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import ToggleButton from 'primevue/togglebutton'
import { useConfigStore } from '@/stores/config'

const props = withDefaults(defineProps<{
  modelValue: string
  placeholder?: string
  readonly?: boolean
  minHeight?: string
  maxHeight?: string
}>(), {
  placeholder: '',
  readonly: false,
  minHeight: '200px',
  maxHeight: '400px'
})

const emit = defineEmits<{
  'update:modelValue': [value: string]
  change: [value: string]
}>()

const configStore = useConfigStore()

const editorContainer = ref<HTMLElement | null>(null)
const searchInputRef = ref<HTMLInputElement | null>(null)
let editorView: EditorView | null = null
const readonlyCompartment = new Compartment()
const themeCompartment = new Compartment()

// 搜索状态
const showSearch = ref(false)
const searchQuery = ref('')
const useRegex = ref(false)
const caseSensitive = ref(false)
const invertSearch = ref(false)
const matchCount = ref(0)
const currentMatchIndex = ref(0)

// HTTP 语法高亮定义
const httpLanguage = StreamLanguage.define({
  token(stream, _state) {
    // 请求行 (GET /path HTTP/1.1)
    if (stream.sol()) {
      if (stream.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s/)) {
        return 'keyword'
      }
      if (stream.match(/^HTTP\/[\d.]+\s+\d+/)) {
        return 'keyword'
      }
      // Header名称
      if (stream.match(/^[\w-]+(?=:)/)) {
        return 'propertyName'
      }
    }
    
    // Header冒号后的值
    if (stream.match(/^:\s*/)) {
      return 'punctuation'
    }
    
    // URL路径
    if (stream.match(/^\/[^\s]*/)) {
      return 'string'
    }
    
    // HTTP版本
    if (stream.match(/^HTTP\/[\d.]+/)) {
      return 'meta'
    }
    
    // 注入点标记 *
    if (stream.match(/\*/)) {
      return 'deleted' // 用deleted标签来标记注入点
    }
    
    // 数字
    if (stream.match(/^\d+/)) {
      return 'number'
    }
    
    // 默认
    stream.next()
    return null
  }
})

// 高亮样式
const httpHighlightStyle = HighlightStyle.define([
  { tag: tags.keyword, color: '#c678dd', fontWeight: 'bold' },
  { tag: tags.propertyName, color: '#e06c75' },
  { tag: tags.string, color: '#98c379' },
  { tag: tags.meta, color: '#61afef' },
  { tag: tags.punctuation, color: '#abb2bf' },
  { tag: tags.number, color: '#d19a66' },
  { tag: tags.deleted, color: '#ff0000', fontWeight: 'bold', backgroundColor: 'rgba(255,0,0,0.2)' }
])

// 基础主题样式
const baseThemeStyles = {
  '&': {
    fontSize: '13px',
    fontFamily: "'Consolas', 'Monaco', 'Courier New', monospace"
  },
  '.cm-lineNumbers .cm-gutterElement': {
    padding: '0 8px 0 12px',
    minWidth: '40px'
  },
  '&.cm-focused': {
    outline: 'none'
  },
  '.cm-scroller': {
    overflow: 'auto'
  }
}

// 浅色主题
const lightTheme = EditorView.theme({
  ...baseThemeStyles,
  '.cm-content': {
    caretColor: '#528bff',
    padding: '8px 0'
  },
  '.cm-gutters': {
    backgroundColor: '#f8f9fa',
    color: '#6c757d',
    border: 'none',
    borderRight: '1px solid #e9ecef'
  },
  '.cm-activeLine': {
    backgroundColor: 'rgba(99, 102, 241, 0.08)'
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'rgba(99, 102, 241, 0.1)'
  },
  '.cm-selectionMatch': {
    backgroundColor: 'rgba(255, 235, 59, 0.4)'
  },
  '.cm-searchMatch': {
    backgroundColor: 'rgba(255, 193, 7, 0.4)',
    outline: '1px solid rgba(255, 152, 0, 0.5)'
  },
  '.cm-searchMatch.cm-searchMatch-selected': {
    backgroundColor: 'rgba(255, 152, 0, 0.6)'
  }
}, { dark: false })

// 暗色主题
const darkTheme = EditorView.theme({
  ...baseThemeStyles,
  '&': {
    ...baseThemeStyles['&'],
    backgroundColor: '#1e293b'
  },
  '.cm-content': {
    caretColor: '#a5b4fc',
    padding: '8px 0',
    color: '#e2e8f0'
  },
  '.cm-gutters': {
    backgroundColor: '#0f172a',
    color: '#64748b',
    border: 'none',
    borderRight: '1px solid #334155'
  },
  '.cm-activeLine': {
    backgroundColor: 'rgba(99, 102, 241, 0.15)'
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'rgba(99, 102, 241, 0.2)'
  },
  '.cm-selectionMatch': {
    backgroundColor: 'rgba(255, 235, 59, 0.3)'
  },
  '.cm-searchMatch': {
    backgroundColor: 'rgba(251, 191, 36, 0.4)',
    outline: '1px solid rgba(251, 191, 36, 0.6)'
  },
  '.cm-searchMatch.cm-searchMatch-selected': {
    backgroundColor: 'rgba(251, 191, 36, 0.6)'
  },
  '.cm-cursor': {
    borderLeftColor: '#a5b4fc'
  },
  '.cm-selectionBackground': {
    backgroundColor: 'rgba(99, 102, 241, 0.3) !important'
  }
}, { dark: true })

// 获取当前主题
function getCurrentTheme() {
  return configStore.theme === 'dark' ? darkTheme : lightTheme
}

const searchPlaceholder = computed(() => {
  let hint = '搜索内容...'
  if (useRegex.value) hint = '正则表达式...'
  return hint
})

const matchInfo = computed(() => {
  if (matchCount.value === 0) return '无匹配'
  if (invertSearch.value) return `${matchCount.value} 行不匹配`
  return `${currentMatchIndex.value}/${matchCount.value}`
})

function createEditorState(content: string): EditorState {
  return EditorState.create({
    doc: content,
    extensions: [
      lineNumbers(),
      highlightActiveLine(),
      highlightActiveLineGutter(),
      history(),
      highlightSelectionMatches(),
      syntaxHighlighting(httpHighlightStyle),
      httpLanguage,
      themeCompartment.of(getCurrentTheme()),
      keymap.of([
        ...defaultKeymap,
        ...historyKeymap,
        ...searchKeymap,
        { key: 'Ctrl-f', run: () => { toggleSearch(); return true } },
        { key: 'Escape', run: () => { closeSearch(); return true } },
        { key: 'F3', run: () => { findNext(); return true } },
        { key: 'Shift-F3', run: () => { findPrev(); return true } }
      ]),
      readonlyCompartment.of(EditorState.readOnly.of(props.readonly)),
      EditorView.updateListener.of(update => {
        if (update.docChanged) {
          const value = update.state.doc.toString()
          emit('update:modelValue', value)
          emit('change', value)
        }
      }),
      EditorView.theme({
        '&': {
          minHeight: props.minHeight,
          maxHeight: props.maxHeight
        }
      })
    ]
  })
}

function initEditor() {
  if (!editorContainer.value) return
  
  editorView = new EditorView({
    state: createEditorState(props.modelValue || ''),
    parent: editorContainer.value
  })
}

function toggleSearch() {
  showSearch.value = !showSearch.value
  if (showSearch.value) {
    nextTick(() => {
      searchInputRef.value?.focus()
    })
  }
}

function closeSearch() {
  showSearch.value = false
  searchQuery.value = ''
  matchCount.value = 0
  currentMatchIndex.value = 0
  
  // 清除高亮
  if (editorView) {
    const emptyQuery = new SearchQuery({ search: '' })
    editorView.dispatch({ effects: setSearchQuery.of(emptyQuery) })
  }
}

function performSearch() {
  if (!editorView || !searchQuery.value) {
    matchCount.value = 0
    currentMatchIndex.value = 0
    return
  }
  
  try {
    let searchString = searchQuery.value
    
    if (invertSearch.value) {
      // 反转模式：高亮不包含关键词的行
      const doc = editorView.state.doc
      let count = 0
      for (let i = 1; i <= doc.lines; i++) {
        const line = doc.line(i).text
        let matches: boolean
        if (useRegex.value) {
          const regex = new RegExp(searchString, caseSensitive.value ? '' : 'i')
          matches = regex.test(line)
        } else {
          matches = caseSensitive.value 
            ? line.includes(searchString)
            : line.toLowerCase().includes(searchString.toLowerCase())
        }
        if (!matches) count++
      }
      matchCount.value = count
      currentMatchIndex.value = count > 0 ? 1 : 0
    } else {
      // 正常搜索
      const query = new SearchQuery({
        search: searchString,
        caseSensitive: caseSensitive.value,
        regexp: useRegex.value
      })
      
      editorView.dispatch({ effects: setSearchQuery.of(query) })
      
      // 计算匹配数
      const doc = editorView.state.doc.toString()
      let regex: RegExp
      if (useRegex.value) {
        regex = new RegExp(searchString, caseSensitive.value ? 'g' : 'gi')
      } else {
        const escaped = searchString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        regex = new RegExp(escaped, caseSensitive.value ? 'g' : 'gi')
      }
      const matches = doc.match(regex)
      matchCount.value = matches ? matches.length : 0
      currentMatchIndex.value = matchCount.value > 0 ? 1 : 0
    }
  } catch (_e) {
    // 正则表达式错误
    matchCount.value = 0
    currentMatchIndex.value = 0
  }
}

function findNext() {
  if (!editorView || !searchQuery.value) return
  cmFindNext(editorView)
  if (currentMatchIndex.value < matchCount.value) {
    currentMatchIndex.value++
  } else {
    currentMatchIndex.value = 1
  }
}

function findPrev() {
  if (!editorView || !searchQuery.value) return
  cmFindPrev(editorView)
  if (currentMatchIndex.value > 1) {
    currentMatchIndex.value--
  } else {
    currentMatchIndex.value = matchCount.value
  }
}

function copyContent() {
  if (props.modelValue) {
    navigator.clipboard.writeText(props.modelValue)
  }
}

function clearContent() {
  emit('update:modelValue', '')
  if (editorView) {
    editorView.dispatch({
      changes: { from: 0, to: editorView.state.doc.length, insert: '' }
    })
  }
}

// 监听搜索参数变化
watch([searchQuery, useRegex, caseSensitive, invertSearch], () => {
  performSearch()
})

// 监听外部值变化
watch(() => props.modelValue, (newVal) => {
  if (editorView && newVal !== editorView.state.doc.toString()) {
    editorView.dispatch({
      changes: { from: 0, to: editorView.state.doc.length, insert: newVal || '' }
    })
  }
})

// 监听readonly变化
watch(() => props.readonly, (newVal) => {
  if (editorView) {
    editorView.dispatch({
      effects: readonlyCompartment.reconfigure(EditorState.readOnly.of(newVal))
    })
  }
})

// 监听主题变化
watch(() => configStore.theme, () => {
  if (editorView) {
    editorView.dispatch({
      effects: themeCompartment.reconfigure(getCurrentTheme())
    })
  }
})

onMounted(() => {
  initEditor()
})

onUnmounted(() => {
  if (editorView) {
    editorView.destroy()
    editorView = null
  }
})

// 暴露方法
defineExpose({
  focus: () => editorView?.focus(),
  toggleSearch,
  getContent: () => props.modelValue
})
</script>

<style scoped lang="scss">
.http-code-editor {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  overflow: hidden;
  background: var(--surface-card);
  
  &.show-search {
    .search-toolbar {
      display: flex;
    }
  }
}

.search-toolbar {
  display: none;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(139, 92, 246, 0.05) 100%);
  border-bottom: 1px solid var(--surface-border);
  flex-wrap: wrap;
  
  .search-input-group {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 200px;
    
    .search-input {
      flex: 1;
      min-width: 150px;
      font-size: 13px;
    }
    
    .match-count {
      font-size: 12px;
      color: var(--text-color-secondary);
      white-space: nowrap;
    }
  }
  
  .search-options {
    display: flex;
    align-items: center;
    gap: 4px;
    
    .separator {
      color: var(--surface-border);
      margin: 0 4px;
    }
    
    .option-toggle {
      font-size: 11px;
      padding: 4px 8px;
      
      :deep(.p-togglebutton-label) {
        font-size: 11px;
      }
    }
  }
}

.editor-wrapper {
  position: relative;
  flex: 1;
}

.editor-container {
  width: 100%;
  
  :deep(.cm-editor) {
    height: 100%;
  }
}

.editor-actions {
  position: absolute;
  top: 4px;
  right: 4px;
  display: flex;
  gap: 2px;
  opacity: 0.5;
  transition: opacity 0.2s;
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 4px;
  padding: 2px;
  
  &:hover {
    opacity: 1;
  }
}
</style>
