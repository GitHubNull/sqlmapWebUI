package com.sqlmapwebui.burp;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.*;

/**
 * 扫描配置管理器
 * 管理默认配置、常用配置和历史配置
 * 配置存储在Burp Suite的扩展设置中
 */
public class ConfigManager {
    
    private static final String KEY_BACKEND_URL = "backendUrl";
    private static final String KEY_DEFAULT_CONFIG = "defaultConfig";
    private static final String KEY_PRESET_CONFIGS = "presetConfigs";
    private static final String KEY_HISTORY_CONFIGS = "historyConfigs";
    private static final String KEY_MAX_HISTORY_SIZE = "maxHistorySize";
    private static final String KEY_AUTO_DEDUPE = "autoDedupe";
    private static final String KEY_MAX_INJECTION_MARK_COUNT = "maxInjectionMarkCount";
    private static final String KEY_SHOW_BINARY_WARNING = "showBinaryWarning";
    
    // 历史记录数量限制
    public static final int MIN_HISTORY_SIZE = 3;
    public static final int MAX_HISTORY_SIZE = 32;
    public static final int DEFAULT_HISTORY_SIZE = 20;
    
    // 注入点标记数量限制（批量标记支持更多报文）
    public static final int MIN_INJECTION_MARK_COUNT = 3;
    public static final int MAX_INJECTION_MARK_COUNT = 15;
    public static final int DEFAULT_INJECTION_MARK_COUNT = 10;
    
    private final IBurpExtenderCallbacks callbacks;
    private final Gson gson;
    
    // 配置数据
    private String backendUrl = "http://localhost:5000";
    private int maxHistorySize = DEFAULT_HISTORY_SIZE;
    private boolean autoDedupe = true; // 默认开启自动去重
    private int maxInjectionMarkCount = DEFAULT_INJECTION_MARK_COUNT; // 多选报文时允许标记注入点的最大数量
    private boolean showBinaryWarning = false; // 是否显示二进制报文警告
    private ScanConfig defaultConfig;
    private List<ScanConfig> presetConfigs;  // 常用配置
    private List<ScanConfig> historyConfigs; // 历史配置
    
    // 连接状态
    private boolean connected = false;
    
    public ConfigManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.presetConfigs = new ArrayList<>();
        this.historyConfigs = new ArrayList<>();
        
        loadConfigurations();
    }
    
    /**
     * 从Burp扩展设置加载所有配置
     */
    private void loadConfigurations() {
        // 加载后端URL
        String savedUrl = callbacks.loadExtensionSetting(KEY_BACKEND_URL);
        if (savedUrl != null && !savedUrl.isEmpty()) {
            backendUrl = savedUrl;
        }
        
        // 加载历史记录最大数量
        String savedMaxHistory = callbacks.loadExtensionSetting(KEY_MAX_HISTORY_SIZE);
        if (savedMaxHistory != null && !savedMaxHistory.isEmpty()) {
            try {
                int size = Integer.parseInt(savedMaxHistory);
                maxHistorySize = Math.max(MIN_HISTORY_SIZE, Math.min(MAX_HISTORY_SIZE, size));
            } catch (NumberFormatException e) {
                maxHistorySize = DEFAULT_HISTORY_SIZE;
            }
        }
        
        // 加载自动去重配置
        String savedAutoDedupe = callbacks.loadExtensionSetting(KEY_AUTO_DEDUPE);
        if (savedAutoDedupe != null && !savedAutoDedupe.isEmpty()) {
            autoDedupe = Boolean.parseBoolean(savedAutoDedupe);
        }
        
        // 加载注入点标记数量配置
        String savedMaxInjectionMarkCount = callbacks.loadExtensionSetting(KEY_MAX_INJECTION_MARK_COUNT);
        if (savedMaxInjectionMarkCount != null && !savedMaxInjectionMarkCount.isEmpty()) {
            try {
                int count = Integer.parseInt(savedMaxInjectionMarkCount);
                maxInjectionMarkCount = Math.max(MIN_INJECTION_MARK_COUNT, Math.min(MAX_INJECTION_MARK_COUNT, count));
            } catch (NumberFormatException e) {
                maxInjectionMarkCount = DEFAULT_INJECTION_MARK_COUNT;
            }
        }
        
        // 加载二进制报文警告配置
        String savedShowBinaryWarning = callbacks.loadExtensionSetting(KEY_SHOW_BINARY_WARNING);
        if (savedShowBinaryWarning != null && !savedShowBinaryWarning.isEmpty()) {
            showBinaryWarning = Boolean.parseBoolean(savedShowBinaryWarning);
        }
        
        // 加载默认配置
        String defaultConfigJson = callbacks.loadExtensionSetting(KEY_DEFAULT_CONFIG);
        if (defaultConfigJson != null && !defaultConfigJson.isEmpty()) {
            try {
                defaultConfig = ScanConfig.fromJson(defaultConfigJson);
            } catch (Exception e) {
                defaultConfig = ScanConfig.createDefault();
            }
        } else {
            defaultConfig = ScanConfig.createDefault();
        }
        
        // 加载常用配置
        String presetsJson = callbacks.loadExtensionSetting(KEY_PRESET_CONFIGS);
        if (presetsJson != null && !presetsJson.isEmpty()) {
            try {
                Type listType = new TypeToken<ArrayList<ScanConfig>>(){}.getType();
                presetConfigs = gson.fromJson(presetsJson, listType);
                if (presetConfigs == null) {
                    presetConfigs = new ArrayList<>();
                }
            } catch (Exception e) {
                presetConfigs = new ArrayList<>();
            }
        }
        
        // 如果没有常用配置，添加预设配置
        if (presetConfigs.isEmpty()) {
            presetConfigs.add(ScanConfig.createDefault());
            presetConfigs.add(ScanConfig.createQuickScan());
            presetConfigs.add(ScanConfig.createDeepScan());
            savePresetConfigs();
        }
        
        // 加载历史配置
        String historyJson = callbacks.loadExtensionSetting(KEY_HISTORY_CONFIGS);
        if (historyJson != null && !historyJson.isEmpty()) {
            try {
                Type listType = new TypeToken<ArrayList<ScanConfig>>(){}.getType();
                historyConfigs = gson.fromJson(historyJson, listType);
                if (historyConfigs == null) {
                    historyConfigs = new ArrayList<>();
                }
            } catch (Exception e) {
                historyConfigs = new ArrayList<>();
            }
        }
    }
    
    // ============ 后端URL管理 ============
    
    public String getBackendUrl() {
        return backendUrl;
    }
    
    public void setBackendUrl(String url) {
        this.backendUrl = url;
        callbacks.saveExtensionSetting(KEY_BACKEND_URL, url);
        // 更改URL后重置连接状态
        this.connected = false;
    }
    
    // ============ 历史记录数量管理 ============
    
    public int getMaxHistorySize() {
        return maxHistorySize;
    }
    
    public void setMaxHistorySize(int size) {
        this.maxHistorySize = Math.max(MIN_HISTORY_SIZE, Math.min(MAX_HISTORY_SIZE, size));
        callbacks.saveExtensionSetting(KEY_MAX_HISTORY_SIZE, String.valueOf(this.maxHistorySize));
        // 如果当前历史记录超过新的最大值，则裁剪
        trimHistory();
    }
    
    // ============ 自动去重配置 ============
    
    public boolean isAutoDedupe() {
        return autoDedupe;
    }
    
    public void setAutoDedupe(boolean enabled) {
        this.autoDedupe = enabled;
        callbacks.saveExtensionSetting(KEY_AUTO_DEDUPE, String.valueOf(enabled));
    }
    
    // ============ 注入点标记数量配置 ============
    
    public int getMaxInjectionMarkCount() {
        return maxInjectionMarkCount;
    }
    
    public void setMaxInjectionMarkCount(int count) {
        this.maxInjectionMarkCount = Math.max(MIN_INJECTION_MARK_COUNT, Math.min(MAX_INJECTION_MARK_COUNT, count));
        callbacks.saveExtensionSetting(KEY_MAX_INJECTION_MARK_COUNT, String.valueOf(this.maxInjectionMarkCount));
    }
    
    // ============ 二进制报文警告配置 ============
    
    public boolean isShowBinaryWarning() {
        return showBinaryWarning;
    }
    
    public void setShowBinaryWarning(boolean show) {
        this.showBinaryWarning = show;
        callbacks.saveExtensionSetting(KEY_SHOW_BINARY_WARNING, String.valueOf(show));
    }
    
    // ============ 连接状态管理 ============
    
    public boolean isConnected() {
        return connected;
    }
    
    public void setConnected(boolean connected) {
        this.connected = connected;
    }
    
    // ============ 默认配置管理 ============
    
    public ScanConfig getDefaultConfig() {
        return defaultConfig;
    }
    
    public void setDefaultConfig(ScanConfig config) {
        this.defaultConfig = config;
        callbacks.saveExtensionSetting(KEY_DEFAULT_CONFIG, config.toJson());
    }
    
    // ============ 常用配置管理 ============
    
    public List<ScanConfig> getPresetConfigs() {
        return Collections.unmodifiableList(presetConfigs);
    }
    
    public void addPresetConfig(ScanConfig config) {
        // 检查是否已存在同名配置
        presetConfigs.removeIf(c -> c.getName().equals(config.getName()));
        presetConfigs.add(config);
        savePresetConfigs();
    }
    
    public void updatePresetConfig(String oldName, ScanConfig newConfig) {
        for (int i = 0; i < presetConfigs.size(); i++) {
            if (presetConfigs.get(i).getName().equals(oldName)) {
                presetConfigs.set(i, newConfig);
                break;
            }
        }
        savePresetConfigs();
    }
    
    public void removePresetConfig(String name) {
        presetConfigs.removeIf(c -> c.getName().equals(name));
        savePresetConfigs();
    }
    
    public ScanConfig getPresetConfig(String name) {
        for (ScanConfig config : presetConfigs) {
            if (config.getName().equals(name)) {
                return config;
            }
        }
        return null;
    }
    
    private void savePresetConfigs() {
        callbacks.saveExtensionSetting(KEY_PRESET_CONFIGS, gson.toJson(presetConfigs));
    }
    
    // ============ 历史配置管理 ============
    
    public List<ScanConfig> getHistoryConfigs() {
        return Collections.unmodifiableList(historyConfigs);
    }
    
    public void addToHistory(ScanConfig config) {
        // 创建历史记录副本，带时间戳
        ScanConfig historyEntry = config.copy();
        historyEntry.updateLastUsed();
        historyEntry.setName(config.getName() + " @ " + formatTimestamp(historyEntry.getLastUsedAt()));
        
        // 添加到历史列表开头
        historyConfigs.add(0, historyEntry);
        
        // 限制历史记录数量
        trimHistory();
        
        saveHistoryConfigs();
    }
    
    public void clearHistory() {
        historyConfigs.clear();
        saveHistoryConfigs();
    }
    
    /**
     * 删除指定索引的历史记录
     * @param indices 要删除的索引列表，必须是升序排列
     */
    public void removeHistoryByIndices(int[] indices) {
        // 从后往前删除，避免索引变化
        for (int i = indices.length - 1; i >= 0; i--) {
            int idx = indices[i];
            if (idx >= 0 && idx < historyConfigs.size()) {
                historyConfigs.remove(idx);
            }
        }
        saveHistoryConfigs();
    }
    
    /**
     * 获取历史记录数量
     */
    public int getHistorySize() {
        return historyConfigs.size();
    }
    
    private void trimHistory() {
        while (historyConfigs.size() > maxHistorySize) {
            historyConfigs.remove(historyConfigs.size() - 1);
        }
        saveHistoryConfigs();
    }
    
    private void saveHistoryConfigs() {
        callbacks.saveExtensionSetting(KEY_HISTORY_CONFIGS, gson.toJson(historyConfigs));
    }
    
    private String formatTimestamp(long timestamp) {
        return new java.text.SimpleDateFormat("MM-dd HH:mm").format(new Date(timestamp));
    }
    
    // ============ 获取所有可选配置 ============
    
    /**
     * 获取配置选择列表（用于下拉菜单）
     * 包括：默认配置、常用配置、历史配置
     */
    public List<ConfigOption> getAllConfigOptions() {
        List<ConfigOption> options = new ArrayList<>();
        
        // 默认配置
        options.add(new ConfigOption("【默认】" + defaultConfig.getName(), defaultConfig, ConfigType.DEFAULT));
        
        // 分隔符
        options.add(ConfigOption.createSeparator("── 常用配置 ──"));
        
        // 常用配置
        for (ScanConfig config : presetConfigs) {
            options.add(new ConfigOption(config.getName(), config, ConfigType.PRESET));
        }
        
        // 历史配置
        if (!historyConfigs.isEmpty()) {
            options.add(ConfigOption.createSeparator("── 历史记录 ──"));
            for (ScanConfig config : historyConfigs) {
                options.add(new ConfigOption(config.getName(), config, ConfigType.HISTORY));
            }
        }
        
        return options;
    }
    
    // ============ 配置选项包装类 ============
    
    public enum ConfigType {
        DEFAULT, PRESET, HISTORY, SEPARATOR
    }
    
    public static class ConfigOption {
        private final String displayName;
        private final ScanConfig config;
        private final ConfigType type;
        
        public ConfigOption(String displayName, ScanConfig config, ConfigType type) {
            this.displayName = displayName;
            this.config = config;
            this.type = type;
        }
        
        public static ConfigOption createSeparator(String label) {
            return new ConfigOption(label, null, ConfigType.SEPARATOR);
        }
        
        public String getDisplayName() { return displayName; }
        public ScanConfig getConfig() { return config; }
        public ConfigType getType() { return type; }
        public boolean isSeparator() { return type == ConfigType.SEPARATOR; }
        
        @Override
        public String toString() {
            return displayName;
        }
    }
}
