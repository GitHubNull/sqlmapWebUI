package com.sqlmapwebui.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.*;

/**
 * 扫描配置管理器 (Montoya API版本)
 * 管理默认配置、常用配置和历史配置
 * 配置存储在Burp Suite的扩展设置中
 */
public class ConfigManager {
    
    private static final String KEY_BACKEND_URL = "backendUrl";
    private static final String KEY_DEFAULT_CONFIG = "defaultConfig";
    private static final String KEY_PRESET_CONFIGS = "presetConfigs";
    private static final String KEY_HISTORY_CONFIGS = "historyConfigs";
    private static final int MAX_HISTORY_SIZE = 20;
    
    private final MontoyaApi api;
    private final PersistedObject persistence;
    private final Gson gson;
    
    // 配置数据
    private String backendUrl = "http://localhost:5000";
    private ScanConfig defaultConfig;
    private List<ScanConfig> presetConfigs;  // 常用配置
    private List<ScanConfig> historyConfigs; // 历史配置
    
    public ConfigManager(MontoyaApi api) {
        this.api = api;
        this.persistence = api.persistence().extensionData();
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
        String savedUrl = persistence.getString(KEY_BACKEND_URL);
        if (savedUrl != null && !savedUrl.isEmpty()) {
            backendUrl = savedUrl;
        }
        
        // 加载默认配置
        String defaultConfigJson = persistence.getString(KEY_DEFAULT_CONFIG);
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
        String presetsJson = persistence.getString(KEY_PRESET_CONFIGS);
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
        String historyJson = persistence.getString(KEY_HISTORY_CONFIGS);
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
        persistence.setString(KEY_BACKEND_URL, url);
    }
    
    // ============ 默认配置管理 ============
    
    public ScanConfig getDefaultConfig() {
        return defaultConfig;
    }
    
    public void setDefaultConfig(ScanConfig config) {
        this.defaultConfig = config;
        persistence.setString(KEY_DEFAULT_CONFIG, config.toJson());
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
        persistence.setString(KEY_PRESET_CONFIGS, gson.toJson(presetConfigs));
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
        while (historyConfigs.size() > MAX_HISTORY_SIZE) {
            historyConfigs.remove(historyConfigs.size() - 1);
        }
        
        saveHistoryConfigs();
    }
    
    public void clearHistory() {
        historyConfigs.clear();
        saveHistoryConfigs();
    }
    
    private void saveHistoryConfigs() {
        persistence.setString(KEY_HISTORY_CONFIGS, gson.toJson(historyConfigs));
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
