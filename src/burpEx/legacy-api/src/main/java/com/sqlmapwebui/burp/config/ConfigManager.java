package com.sqlmapwebui.burp.config;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sqlmapwebui.burp.model.TitleConfig;
import com.sqlmapwebui.burp.model.TitleRule;
import com.sqlmapwebui.burp.model.TitleSourceType;
import com.sqlmapwebui.burp.model.RegexSource;

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
    private static final String KEY_SCAN_CONFIG_SOURCE = "scanConfigSource";  // 扫描配置来源
    private static final String KEY_SELECTED_PRESET_NAME = "selectedPresetName";  // 选中的常用配置名称
    
    // ==================== 剪贴板功能配置 ====================
    private static final String KEY_CLIPBOARD_AUTO_COPY = "clipboardAutoCopy";  // 是否自动复制
    private static final String KEY_CLIPBOARD_TEMP_DIR = "clipboardTempDir";  // 临时目录
    
    // ==================== 直接执行功能配置 ====================
    private static final String KEY_DIRECT_PYTHON_PATH = "directPythonPath";  // Python路径
    private static final String KEY_DIRECT_SQLMAP_PATH = "directSqlmapPath";  // SQLMap路径
    private static final String KEY_DIRECT_TERMINAL_TYPE = "directTerminalType";  // 终端类型
    private static final String KEY_DIRECT_KEEP_TERMINAL = "directKeepTerminal";  // 保持终端打开
    
    // ==================== 标题配置 ====================
    private static final String KEY_TITLE_SOURCE_TYPE = "titleSourceType";
    private static final String KEY_TITLE_FIXED_VALUE = "titleFixedValue";
    private static final String KEY_TITLE_PATH_SUB_START = "titlePathSubStart";
    private static final String KEY_TITLE_PATH_SUB_END = "titlePathSubEnd";
    private static final String KEY_TITLE_REGEX_PATTERN = "titleRegexPattern";
    private static final String KEY_TITLE_REGEX_GROUP = "titleRegexGroup";
    private static final String KEY_TITLE_REGEX_SOURCE = "titleRegexSource";
    private static final String KEY_TITLE_JSON_PATH = "titleJsonPath";
    private static final String KEY_TITLE_XPATH = "titleXpath";
    private static final String KEY_TITLE_FORM_FIELD = "titleFormField";
    private static final String KEY_TITLE_FALLBACK = "titleFallback";
    private static final String KEY_TITLE_MAX_LENGTH = "titleMaxLength";
    
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
    private String backendUrl = "http://localhost:8775";
    private int maxHistorySize = DEFAULT_HISTORY_SIZE;
    private boolean autoDedupe = true; // 默认开启自动去重
    private int maxInjectionMarkCount = DEFAULT_INJECTION_MARK_COUNT; // 多选报文时允许标记注入点的最大数量
    private boolean showBinaryWarning = false; // 是否显示二进制报文警告
    private ScanConfig defaultConfig;
    private List<ScanConfig> presetConfigs;  // 常用配置
    private List<ScanConfig> historyConfigs; // 历史配置
    
    // 扫描配置来源选择
    private ScanConfigSource scanConfigSource = ScanConfigSource.DEFAULT;  // 默认使用默认配置
    private String selectedPresetName = null;  // 选中的常用配置名称
    
    // 常用配置数据库引用
    private PresetConfigDatabase presetDatabase;

    // 命令行执行配置（从数据库加载）
    private CommandExecConfig commandExecConfig;
    
    // 连接状态
    private boolean connected = false;
    
    // ==================== 剪贴板功能配置 ====================
    private boolean clipboardAutoCopy = true;  // 是否自动复制到剪贴板（默认自动）
    private String clipboardTempDir = "";  // 临时文件目录（空则使用系统默认）
    
    // ==================== 直接执行功能配置 ====================
    private String directPythonPath = "";  // Python解释器路径
    private String directSqlmapPath = "";  // SQLMap脚本路径
    private TerminalType directTerminalType = TerminalType.AUTO;  // 终端类型
    private boolean directKeepTerminal = true;  // 执行后保持终端打开
    private String scriptTempDir = "";  // 执行脚本临时目录
    
    // ==================== 标题配置 ====================
    private TitleSourceType titleSourceType = TitleSourceType.URL_PATH;
    private String titleFixedValue = "SQLMap";
    private String titlePathSubStart = "0";
    private String titlePathSubEnd = "-0";
    private String titleRegexPattern = "";
    private int titleRegexGroup = 1;
    private RegexSource titleRegexSource = RegexSource.URL;
    private String titleJsonPath = "$.api";
    private String titleXpath = "//method";
    private String titleFormField = "action";
    private String titleFallback = "SQLMap";
    private int titleMaxLength = 50;
    
    /**
     * 终端类型枚举
     */
    public enum TerminalType {
        AUTO,           // 自动检测操作系统
        CMD,            // Windows CMD
        POWERSHELL,     // Windows PowerShell
        GNOME_TERMINAL, // Linux GNOME Terminal
        XTERM,          // Linux xterm
        TERMINAL_APP,   // macOS Terminal.app
        ITERM            // macOS iTerm2
    }

    /**
     * 扫描配置来源枚举
     */
    public enum ScanConfigSource {
        DEFAULT,   // 使用默认配置
        PRESET,    // 使用常用配置
        HISTORY    // 使用最近历史配置
    }
    
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
        
        // 加载扫描配置来源
        String savedConfigSource = callbacks.loadExtensionSetting(KEY_SCAN_CONFIG_SOURCE);
        if (savedConfigSource != null && !savedConfigSource.isEmpty()) {
            try {
                scanConfigSource = ScanConfigSource.valueOf(savedConfigSource);
            } catch (IllegalArgumentException e) {
                scanConfigSource = ScanConfigSource.DEFAULT;
            }
        }
        
        // 加载选中的常用配置名称
        String savedPresetName = callbacks.loadExtensionSetting(KEY_SELECTED_PRESET_NAME);
        if (savedPresetName != null && !savedPresetName.isEmpty()) {
            selectedPresetName = savedPresetName;
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

        // ==================== 加载剪贴板功能配置 ====================
        String savedClipboardAutoCopy = callbacks.loadExtensionSetting(KEY_CLIPBOARD_AUTO_COPY);
        if (savedClipboardAutoCopy != null && !savedClipboardAutoCopy.isEmpty()) {
            clipboardAutoCopy = Boolean.parseBoolean(savedClipboardAutoCopy);
        }

        String savedClipboardTempDir = callbacks.loadExtensionSetting(KEY_CLIPBOARD_TEMP_DIR);
        if (savedClipboardTempDir != null && !savedClipboardTempDir.isEmpty()) {
            clipboardTempDir = savedClipboardTempDir;
        }

        // ==================== 加载直接执行功能配置 ====================
        String savedDirectPythonPath = callbacks.loadExtensionSetting(KEY_DIRECT_PYTHON_PATH);
        if (savedDirectPythonPath != null && !savedDirectPythonPath.isEmpty()) {
            directPythonPath = savedDirectPythonPath;
        }

        String savedDirectSqlmapPath = callbacks.loadExtensionSetting(KEY_DIRECT_SQLMAP_PATH);
        if (savedDirectSqlmapPath != null && !savedDirectSqlmapPath.isEmpty()) {
            directSqlmapPath = savedDirectSqlmapPath;
        }

        String savedDirectTerminalType = callbacks.loadExtensionSetting(KEY_DIRECT_TERMINAL_TYPE);
        if (savedDirectTerminalType != null && !savedDirectTerminalType.isEmpty()) {
            try {
                directTerminalType = TerminalType.valueOf(savedDirectTerminalType);
            } catch (IllegalArgumentException e) {
                directTerminalType = TerminalType.AUTO;
            }
        }

        String savedDirectKeepTerminal = callbacks.loadExtensionSetting(KEY_DIRECT_KEEP_TERMINAL);
        if (savedDirectKeepTerminal != null && !savedDirectKeepTerminal.isEmpty()) {
            directKeepTerminal = Boolean.parseBoolean(savedDirectKeepTerminal);
        }
        
        // ==================== 加载标题配置 ====================
        String savedTitleSourceType = callbacks.loadExtensionSetting(KEY_TITLE_SOURCE_TYPE);
        if (savedTitleSourceType != null && !savedTitleSourceType.isEmpty()) {
            try {
                titleSourceType = TitleSourceType.valueOf(savedTitleSourceType);
            } catch (IllegalArgumentException e) {
                titleSourceType = TitleSourceType.URL_PATH;
            }
        }
        
        String savedTitleFixedValue = callbacks.loadExtensionSetting(KEY_TITLE_FIXED_VALUE);
        if (savedTitleFixedValue != null && !savedTitleFixedValue.isEmpty()) {
            titleFixedValue = savedTitleFixedValue;
        }
        
        String savedTitlePathSubStart = callbacks.loadExtensionSetting(KEY_TITLE_PATH_SUB_START);
        if (savedTitlePathSubStart != null && !savedTitlePathSubStart.isEmpty()) {
            titlePathSubStart = savedTitlePathSubStart;
        }
        
        String savedTitlePathSubEnd = callbacks.loadExtensionSetting(KEY_TITLE_PATH_SUB_END);
        if (savedTitlePathSubEnd != null && !savedTitlePathSubEnd.isEmpty()) {
            titlePathSubEnd = savedTitlePathSubEnd;
        }
        
        String savedTitleRegexPattern = callbacks.loadExtensionSetting(KEY_TITLE_REGEX_PATTERN);
        if (savedTitleRegexPattern != null) {
            titleRegexPattern = savedTitleRegexPattern;
        }
        
        String savedTitleRegexGroup = callbacks.loadExtensionSetting(KEY_TITLE_REGEX_GROUP);
        if (savedTitleRegexGroup != null && !savedTitleRegexGroup.isEmpty()) {
            try {
                titleRegexGroup = Integer.parseInt(savedTitleRegexGroup);
            } catch (NumberFormatException e) {
                titleRegexGroup = 1;
            }
        }
        
        String savedTitleRegexSource = callbacks.loadExtensionSetting(KEY_TITLE_REGEX_SOURCE);
        if (savedTitleRegexSource != null && !savedTitleRegexSource.isEmpty()) {
            try {
                titleRegexSource = RegexSource.valueOf(savedTitleRegexSource);
            } catch (IllegalArgumentException e) {
                titleRegexSource = RegexSource.URL;
            }
        }
        
        String savedTitleJsonPath = callbacks.loadExtensionSetting(KEY_TITLE_JSON_PATH);
        if (savedTitleJsonPath != null && !savedTitleJsonPath.isEmpty()) {
            titleJsonPath = savedTitleJsonPath;
        }
        
        String savedTitleXpath = callbacks.loadExtensionSetting(KEY_TITLE_XPATH);
        if (savedTitleXpath != null && !savedTitleXpath.isEmpty()) {
            titleXpath = savedTitleXpath;
        }
        
        String savedTitleFormField = callbacks.loadExtensionSetting(KEY_TITLE_FORM_FIELD);
        if (savedTitleFormField != null && !savedTitleFormField.isEmpty()) {
            titleFormField = savedTitleFormField;
        }
        
        String savedTitleFallback = callbacks.loadExtensionSetting(KEY_TITLE_FALLBACK);
        if (savedTitleFallback != null && !savedTitleFallback.isEmpty()) {
            titleFallback = savedTitleFallback;
        }
        
        String savedTitleMaxLength = callbacks.loadExtensionSetting(KEY_TITLE_MAX_LENGTH);
        if (savedTitleMaxLength != null && !savedTitleMaxLength.isEmpty()) {
            try {
                titleMaxLength = Integer.parseInt(savedTitleMaxLength);
            } catch (NumberFormatException e) {
                titleMaxLength = 50;
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
    
    // ============ 扫描配置来源管理 ============
    
    public ScanConfigSource getScanConfigSource() {
        return scanConfigSource;
    }
    
    public void setScanConfigSource(ScanConfigSource source) {
        this.scanConfigSource = source;
        callbacks.saveExtensionSetting(KEY_SCAN_CONFIG_SOURCE, source.name());
    }
    
    public String getSelectedPresetName() {
        return selectedPresetName;
    }
    
    public void setSelectedPresetName(String name) {
        this.selectedPresetName = name;
        if (name != null) {
            callbacks.saveExtensionSetting(KEY_SELECTED_PRESET_NAME, name);
        }
    }
    
    /**
     * 设置常用配置数据库引用
     * 同时从数据库加载命令行执行配置
     */
    public void setPresetDatabase(PresetConfigDatabase database) {
        this.presetDatabase = database;
        loadCommandExecConfig();
    }
    
    /**
     * 根据用户选择的配置来源获取扫描配置
     * 这是右键菜单发送扫描时应该使用的方法
     */
    public ScanConfig getSelectedScanConfig() {
        switch (scanConfigSource) {
            case PRESET:
                // 尝试从PresetConfigDatabase获取
                if (presetDatabase != null && selectedPresetName != null) {
                    PresetConfig presetConfig = presetDatabase.getConfigByName(selectedPresetName);
                    if (presetConfig != null) {
                        String paramString = presetConfig.getParameterString();
                        if (paramString != null && !paramString.trim().isEmpty()) {
                            // 使用完整的ScanConfigParser解析参数字符串
                            ParseResult result = ScanConfigParser.parse(paramString);
                            if (result.isSuccess() && result.getConfig() != null) {
                                ScanConfig config = result.getConfig();
                                config.setName(presetConfig.getName());
                                config.setDescription(presetConfig.getDescription());
                                return config;
                            }
                        }
                        // 如果参数字符串为空或解析失败，返回默认配置但保留名称
                        ScanConfig fallback = ScanConfig.createDefault();
                        fallback.setName(presetConfig.getName());
                        fallback.setDescription(presetConfig.getDescription());
                        return fallback;
                    }
                }
                // 如果数据库不可用，尝试从内存列表获取
                if (selectedPresetName != null) {
                    ScanConfig presetConfig = getPresetConfig(selectedPresetName);
                    if (presetConfig != null) {
                        return presetConfig;
                    }
                }
                // 回退到默认配置
                return defaultConfig;
                
            case HISTORY:
                if (!historyConfigs.isEmpty()) {
                    return historyConfigs.get(0);
                }
                // 回退到默认配置
                return defaultConfig;
                
            case DEFAULT:
            default:
                return defaultConfig;
        }
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

    // ============ 剪贴板功能配置管理 ============

    /**
     * 获取是否自动复制到剪贴板
     */
    public boolean isClipboardAutoCopy() {
        return clipboardAutoCopy;
    }

    /**
     * 设置是否自动复制到剪贴板
     */
    public void setClipboardAutoCopy(boolean autoCopy) {
        this.clipboardAutoCopy = autoCopy;
        callbacks.saveExtensionSetting(KEY_CLIPBOARD_AUTO_COPY, String.valueOf(autoCopy));
    }

    /**
     * 获取临时文件目录
     */
    public String getClipboardTempDir() {
        return clipboardTempDir;
    }

    /**
     * 设置临时文件目录
     */
    public void setClipboardTempDir(String tempDir) {
        this.clipboardTempDir = tempDir != null ? tempDir : "";
        callbacks.saveExtensionSetting(KEY_CLIPBOARD_TEMP_DIR, this.clipboardTempDir);
    }

    // ============ 直接执行功能配置管理 ============

    /**
     * 获取 Python 解释器路径
     */
    public String getDirectPythonPath() {
        return directPythonPath;
    }

    /**
     * 设置 Python 解释器路径
     */
    public void setDirectPythonPath(String path) {
        this.directPythonPath = path != null ? path : "";
        callbacks.saveExtensionSetting(KEY_DIRECT_PYTHON_PATH, this.directPythonPath);
    }

    /**
     * 获取 SQLMap 脚本路径
     */
    public String getDirectSqlmapPath() {
        return directSqlmapPath;
    }

    /**
     * 设置 SQLMap 脚本路径
     */
    public void setDirectSqlmapPath(String path) {
        this.directSqlmapPath = path != null ? path : "";
        callbacks.saveExtensionSetting(KEY_DIRECT_SQLMAP_PATH, this.directSqlmapPath);
    }

    /**
     * 获取终端类型
     */
    public TerminalType getDirectTerminalType() {
        return directTerminalType;
    }

    /**
     * 设置终端类型
     */
    public void setDirectTerminalType(TerminalType type) {
        this.directTerminalType = type != null ? type : TerminalType.AUTO;
        callbacks.saveExtensionSetting(KEY_DIRECT_TERMINAL_TYPE, this.directTerminalType.name());
    }

    /**
     * 获取执行后是否保持终端打开
     */
    public boolean isDirectKeepTerminal() {
        return directKeepTerminal;
    }

    /**
     * 设置执行后是否保持终端打开
     */
    public void setDirectKeepTerminal(boolean keepTerminal) {
        this.directKeepTerminal = keepTerminal;
        callbacks.saveExtensionSetting(KEY_DIRECT_KEEP_TERMINAL, String.valueOf(keepTerminal));
    }

    /**
     * 获取执行脚本临时目录
     */
    public String getScriptTempDir() {
        return scriptTempDir;
    }

    /**
     * 设置执行脚本临时目录
     */
    public void setScriptTempDir(String scriptTempDir) {
        this.scriptTempDir = scriptTempDir != null ? scriptTempDir : "";
    }
    
    // ============ 标题配置管理 ============
    
    public TitleSourceType getTitleSourceType() {
        return titleSourceType;
    }
    
    public void setTitleSourceType(TitleSourceType type) {
        this.titleSourceType = type != null ? type : TitleSourceType.URL_PATH;
        callbacks.saveExtensionSetting(KEY_TITLE_SOURCE_TYPE, this.titleSourceType.name());
    }
    
    public String getTitleFixedValue() {
        return titleFixedValue;
    }
    
    public void setTitleFixedValue(String value) {
        this.titleFixedValue = value != null ? value : "SQLMap";
        callbacks.saveExtensionSetting(KEY_TITLE_FIXED_VALUE, this.titleFixedValue);
    }
    
    public String getTitlePathSubStart() {
        return titlePathSubStart;
    }
    
    public void setTitlePathSubStart(String start) {
        this.titlePathSubStart = start != null ? start : "0";
        callbacks.saveExtensionSetting(KEY_TITLE_PATH_SUB_START, this.titlePathSubStart);
    }
    
    public String getTitlePathSubEnd() {
        return titlePathSubEnd;
    }
    
    public void setTitlePathSubEnd(String end) {
        this.titlePathSubEnd = end != null ? end : "-0";
        callbacks.saveExtensionSetting(KEY_TITLE_PATH_SUB_END, this.titlePathSubEnd);
    }
    
    public String getTitleRegexPattern() {
        return titleRegexPattern;
    }
    
    public void setTitleRegexPattern(String pattern) {
        this.titleRegexPattern = pattern != null ? pattern : "";
        callbacks.saveExtensionSetting(KEY_TITLE_REGEX_PATTERN, this.titleRegexPattern);
    }
    
    public int getTitleRegexGroup() {
        return titleRegexGroup;
    }
    
    public void setTitleRegexGroup(int group) {
        this.titleRegexGroup = Math.max(0, group);
        callbacks.saveExtensionSetting(KEY_TITLE_REGEX_GROUP, String.valueOf(this.titleRegexGroup));
    }
    
    public RegexSource getTitleRegexSource() {
        return titleRegexSource;
    }
    
    public void setTitleRegexSource(RegexSource source) {
        this.titleRegexSource = source != null ? source : RegexSource.URL;
        callbacks.saveExtensionSetting(KEY_TITLE_REGEX_SOURCE, this.titleRegexSource.name());
    }
    
    public String getTitleJsonPath() {
        return titleJsonPath;
    }
    
    public void setTitleJsonPath(String path) {
        this.titleJsonPath = path != null ? path : "$.api";
        callbacks.saveExtensionSetting(KEY_TITLE_JSON_PATH, this.titleJsonPath);
    }
    
    public String getTitleXPath() {
        return titleXpath;
    }
    
    public void setTitleXPath(String path) {
        this.titleXpath = path != null ? path : "//method";
        callbacks.saveExtensionSetting(KEY_TITLE_XPATH, this.titleXpath);
    }
    
    public String getTitleFormField() {
        return titleFormField;
    }
    
    public void setTitleFormField(String field) {
        this.titleFormField = field != null ? field : "action";
        callbacks.saveExtensionSetting(KEY_TITLE_FORM_FIELD, this.titleFormField);
    }
    
    public String getTitleFallback() {
        return titleFallback;
    }
    
    public void setTitleFallback(String fallback) {
        this.titleFallback = fallback != null ? fallback : "SQLMap";
        callbacks.saveExtensionSetting(KEY_TITLE_FALLBACK, this.titleFallback);
    }
    
    public int getTitleMaxLength() {
        return titleMaxLength;
    }
    
    public void setTitleMaxLength(int maxLength) {
        this.titleMaxLength = Math.max(1, Math.min(200, maxLength));
        callbacks.saveExtensionSetting(KEY_TITLE_MAX_LENGTH, String.valueOf(this.titleMaxLength));
    }
    
    /**
     * 获取标题配置对象
     */
    public TitleConfig getTitleConfig() {
        return new TitleConfig(
            titleSourceType,
            titleFixedValue,
            titlePathSubStart,
            titlePathSubEnd,
            titleRegexPattern,
            titleRegexGroup,
            titleRegexSource,
            titleJsonPath,
            titleXpath,
            titleFormField,
            titleFallback,
            titleMaxLength
        );
    }
    
    /**
     * 从标题配置对象批量设置
     */
    public void setTitleConfig(TitleConfig config) {
        if (config == null) return;
        setTitleSourceType(config.getSourceType());
        setTitleFixedValue(config.getFixedValue());
        setTitlePathSubStart(config.getPathSubStart());
        setTitlePathSubEnd(config.getPathSubEnd());
        setTitleRegexPattern(config.getRegexPattern());
        setTitleRegexGroup(config.getRegexGroup());
        setTitleRegexSource(config.getRegexSource());
        setTitleJsonPath(config.getJsonPath());
        setTitleXPath(config.getXpath());
        setTitleFormField(config.getFormField());
        setTitleFallback(config.getFallback());
        setTitleMaxLength(config.getMaxLength());
    }
    
    // ==================== 标题规则列表管理 ====================
    
    private static final String KEY_TITLE_RULES = "titleRules";
    private List<TitleRule> titleRules = null;
    
    /**
     * 获取标题规则列表
     * 首次访问时从存储加载，如果为空则创建默认规则
     */
    public List<TitleRule> getTitleRules() {
        if (titleRules == null) {
            loadTitleRules();
        }
        return new ArrayList<>(titleRules);
    }
    
    /**
     * 加载标题规则列表
     */
    private void loadTitleRules() {
        String json = callbacks.loadExtensionSetting(KEY_TITLE_RULES);
        if (json != null && !json.isEmpty()) {
            try {
                Type listType = new TypeToken<List<TitleRule>>() {}.getType();
                List<TitleRule> loaded = gson.fromJson(json, listType);
                if (loaded != null && !loaded.isEmpty()) {
                    titleRules = loaded;
                    // 确保有默认规则
                    boolean hasDefault = titleRules.stream()
                        .anyMatch(r -> TitleRule.DEFAULT_RULE_ID.equals(r.getId()));
                    if (!hasDefault) {
                        titleRules.add(0, TitleRule.createDefaultRule());
                    }
                    return;
                }
            } catch (Exception e) {
                // 加载失败，使用默认
            }
        }
        // 创建默认规则列表
        titleRules = new ArrayList<>();
        titleRules.add(TitleRule.createDefaultRule());
    }
    
    /**
     * 保存标题规则列表
     */
    public void setTitleRules(List<TitleRule> rules) {
        if (rules == null) {
            titleRules = new ArrayList<>();
            titleRules.add(TitleRule.createDefaultRule());
        } else {
            titleRules = new ArrayList<>(rules);
        }
        String json = gson.toJson(titleRules);
        callbacks.saveExtensionSetting(KEY_TITLE_RULES, json);
    }
    
    /**
     * 添加标题规则
     */
    public void addTitleRule(TitleRule rule) {
        if (titleRules == null) loadTitleRules();
        if (rule.getPriority() == 999) {
            rule.setPriority(titleRules.size());
        }
        titleRules.add(rule);
        String json = gson.toJson(titleRules);
        callbacks.saveExtensionSetting(KEY_TITLE_RULES, json);
    }
    
    /**
     * 更新标题规则
     */
    public void updateTitleRule(TitleRule rule) {
        if (titleRules == null) loadTitleRules();
        for (int i = 0; i < titleRules.size(); i++) {
            if (titleRules.get(i).getId().equals(rule.getId())) {
                rule.touch();
                titleRules.set(i, rule);
                break;
            }
        }
        String json = gson.toJson(titleRules);
        callbacks.saveExtensionSetting(KEY_TITLE_RULES, json);
    }
    
    /**
     * 删除标题规则
     */
    public void deleteTitleRule(String ruleId) {
        if (titleRules == null) loadTitleRules();
        titleRules.removeIf(r -> r.getId().equals(ruleId) && !r.isDefaultRule());
        String json = gson.toJson(titleRules);
        callbacks.saveExtensionSetting(KEY_TITLE_RULES, json);
    }
    
    /**
     * 根据ID获取标题规则
     */
    public TitleRule getTitleRuleById(String id) {
        if (titleRules == null) loadTitleRules();
        return titleRules.stream()
            .filter(r -> r.getId().equals(id))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * 移动规则向上（减小优先级数字）
     */
    public void moveRuleUp(String ruleId) {
        if (titleRules == null) loadTitleRules();
        for (int i = 1; i < titleRules.size(); i++) {
            if (titleRules.get(i).getId().equals(ruleId)) {
                TitleRule rule = titleRules.get(i);
                if (!rule.isDefaultRule()) {
                    TitleRule prev = titleRules.get(i - 1);
                    if (!prev.isDefaultRule()) {
                        int temp = rule.getPriority();
                        rule.setPriority(prev.getPriority());
                        prev.setPriority(temp);
                        titleRules.sort(Comparator.comparingInt(TitleRule::getPriority));
                        saveTitleRulesInternal();
                    }
                }
                break;
            }
        }
    }
    
    /**
     * 移动规则向下（增大优先级数字）
     */
    public void moveRuleDown(String ruleId) {
        if (titleRules == null) loadTitleRules();
        for (int i = 0; i < titleRules.size() - 1; i++) {
            if (titleRules.get(i).getId().equals(ruleId)) {
                TitleRule rule = titleRules.get(i);
                if (!rule.isDefaultRule()) {
                    TitleRule next = titleRules.get(i + 1);
                    int temp = rule.getPriority();
                    rule.setPriority(next.getPriority());
                    next.setPriority(temp);
                    titleRules.sort(Comparator.comparingInt(TitleRule::getPriority));
                    saveTitleRulesInternal();
                }
                break;
            }
        }
    }
    
    /**
     * 内部保存规则列表
     */
    private void saveTitleRulesInternal() {
        String json = gson.toJson(titleRules);
        callbacks.saveExtensionSetting(KEY_TITLE_RULES, json);
    }

    /**
     * 从数据库加载命令行执行配置
     */
    public void loadCommandExecConfig() {
        if (presetDatabase == null) {
            return;
        }

        CommandExecConfig config = presetDatabase.getCommandExecConfig();
        if (config != null) {
            this.commandExecConfig = config;

            // 同步到内存字段
            this.clipboardAutoCopy = config.isAutoCopy();
            this.clipboardTempDir = config.getTempDir();
            this.directPythonPath = config.getPythonPath();
            this.directSqlmapPath = config.getSqlmapPath();
            try {
                this.directTerminalType = TerminalType.valueOf(config.getTerminalType());
            } catch (IllegalArgumentException e) {
                this.directTerminalType = TerminalType.AUTO;
            }
            this.directKeepTerminal = config.isKeepTerminal();
            this.scriptTempDir = config.getScriptTempDir();
            this.titleFallback = config.getTitleFallback();
            this.titleMaxLength = config.getTitleMaxLength();

            // 加载标题规则
            List<TitleRule> rules = config.getTitleRules();
            if (rules != null && !rules.isEmpty()) {
                this.titleRules = new ArrayList<>(rules);
            }
        }
    }

    /**
     * 保存命令行执行配置到数据库
     */
    public void saveCommandExecConfig() {
        if (presetDatabase == null) {
            return;
        }

        CommandExecConfig config = new CommandExecConfig();
        config.setAutoCopy(clipboardAutoCopy);
        config.setTempDir(clipboardTempDir);
        config.setScriptTempDir(scriptTempDir);
        config.setPythonPath(directPythonPath);
        config.setSqlmapPath(directSqlmapPath);
        config.setTerminalType(directTerminalType.name());
        config.setKeepTerminal(directKeepTerminal);
        config.setTitleFallback(titleFallback);
        config.setTitleMaxLength(titleMaxLength);
        if (titleRules != null) {
            config.setTitleRules(new ArrayList<>(titleRules));
        }

        presetDatabase.saveCommandExecConfig(config);
        this.commandExecConfig = config;
    }
}
