<template>
  <div class="search-filter-bar">
    <IconField v-if="showSearch" class="search-field">
      <InputIcon class="pi pi-search" />
      <InputText
        v-model="searchValue"
        :placeholder="searchPlaceholder"
        @input="handleSearch"
      />
    </IconField>
    
    <Select
      v-if="filterOptions.length > 0"
      v-model="selectedFilter"
      :options="filterOptions"
      :option-label="filterLabelKey"
      :option-value="filterValueKey"
      :placeholder="filterPlaceholder"
      @change="handleFilterChange"
      class="filter-select"
    />
    
    <slot name="actions" />
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'

interface FilterOption {
  [key: string]: any
}

interface Props {
  showSearch?: boolean
  searchPlaceholder?: string
  searchDebounce?: number
  filterOptions?: FilterOption[]
  filterPlaceholder?: string
  filterLabelKey?: string
  filterValueKey?: string
  modelValue?: string
  filterValue?: any
}

const props = withDefaults(defineProps<Props>(), {
  showSearch: true,
  searchPlaceholder: '搜索...',
  searchDebounce: 300,
  filterOptions: () => [],
  filterPlaceholder: '筛选',
  filterLabelKey: 'label',
  filterValueKey: 'value',
  modelValue: '',
  filterValue: null
})

const emit = defineEmits<{
  'update:modelValue': [value: string]
  'update:filterValue': [value: any]
  'search': [value: string]
  'filter': [value: any]
}>()

const searchValue = ref(props.modelValue)
const selectedFilter = ref(props.filterValue)
let searchTimeout: ReturnType<typeof setTimeout> | null = null

watch(() => props.modelValue, (newVal) => {
  searchValue.value = newVal
})

watch(() => props.filterValue, (newVal) => {
  selectedFilter.value = newVal
})

function handleSearch() {
  emit('update:modelValue', searchValue.value)
  
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  
  searchTimeout = setTimeout(() => {
    emit('search', searchValue.value)
  }, props.searchDebounce)
}

function handleFilterChange() {
  emit('update:filterValue', selectedFilter.value)
  emit('filter', selectedFilter.value)
}
</script>

<style scoped>
.search-filter-bar {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.search-field {
  flex: 1;
  min-width: 200px;
}

.filter-select {
  min-width: 150px;
}

@media (max-width: 640px) {
  .search-filter-bar {
    flex-direction: column;
    align-items: stretch;
  }
  
  .search-field,
  .filter-select {
    width: 100%;
  }
}
</style>
