package com.sqlmapwebui.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sqlmapwebui.burp.util.TitleConfig;
import com.sqlmapwebui.burp.util.TitleRule;
import com.sqlmapwebui.burp.util.TitleSourceType;
import com.sqlmapwebui.burp.util.RegexSource;

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
    
    // ==================== 终端窗口标题配置 ====================
    private static final String KEY_TITLE_SOURCE_TYPE = "titleSourceType";     // 标题来源类型
    private static final String KEY_TITLE_FIXED_VALUE = "titleFixedValue";     // 固定标题值
    private static final String KEY_TITLE_PATH_SUB_START = "titlePathSubStart"; // URL路径子串起始位置
    private static final String KEY_TITLE_PATH_SUB_END = "titlePathSubEnd";    // URL路径子串结束位置
    private static final String KEY_TITLE_REGEX_PATTERN = "titleRegexPattern"; // 正则表达式模式
    private static final String KEY_TITLE_REGEX_GROUP = "titleRegexGroup";     // 正则捕获组索引
    private static final String KEY_TITLE_REGEX_SOURCE = "titleRegexSource";   // 正则匹配源
    private static final String KEY_TITLE_JSON_PATH = "titleJsonPath";         // JSON Path 表达式
    private static final String KEY_TITLE_XPATH = "titleXPath";                // XPath 表达式
    private static final String KEY_TITLE_FORM_FIELD = "titleFormField";       // 表单字段名
    private static final String KEY_TITLE_FALLBACK = "titleFallback";          // 回退标题
    private static final String KEY_TITLE_MAX_LENGTH = "titleMaxLength";       // 标题最大长度
    private static final String KEY_TITLE_RULES = "titleRules";                // 标题提取规则列表 (JSON)
    
    // 历史记录数量限制
    public static final int MIN_HISTORY_SIZE = 3;
    public static final int MAX_HISTORY_SIZE = 32;
    public static final int DEFAULT_HISTORY_SIZE = 20;
    
    // 注入点标记数量限制（批量标记支持更多报文）
    public static final int MIN_INJECTION_MARK_COUNT = 3;
    public static final int MAX_INJECTION_MARK_COUNT = 15;
    public static final int DEFAULT_INJECTION_MARK_COUNT = 10;
    
    @SuppressWarnings("unused")
    private final MontoyaApi api;
    private final PersistedObject persistence;
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
    
    // ==================== 终端窗口标题配置 ====================
    private TitleSourceType titleSourceType = TitleSourceType.URL_PATH;  // 标题来源类型
    private String titleFixedValue = "SQLMap";           // 固定标题值
    private String titlePathSubStart = "0";              // URL路径子串起始位置
    private String titlePathSubEnd = "-0";               // URL路径子串结束位置
    private String titleRegexPattern = "";               // 正则表达式模式
    private int titleRegexGroup = 1;                     // 正则捕获组索引
    private RegexSource titleRegexSource = RegexSource.URL;  // 正则匹配源
    private String titleJsonPath = "$.api";              // JSON Path 表达式
    private String titleXPath = "//method";              // XPath 表达式
    private String titleFormField = "action";            // 表单字段名
    private String titleFallback = "SQLMap";             // 回退标题
    private int titleMaxLength = 50;                     // 标题最大长度
    private List<TitleRule> titleRules = null;           // 标题提取规则列表 (null表示未初始化)
    
    /**
     * 扫描配置来源枚举
     */
    public enum ScanConfigSource {
        DEFAULT,   // 使用默认配置
        PRESET,    // 使用常用配置
        HISTORY    // 使用最近历史配置
    }
    
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
        
        // 加载历史记录最大数量
        String savedMaxHistory = persistence.getString(KEY_MAX_HISTORY_SIZE);
        if (savedMaxHistory != null && !savedMaxHistory.isEmpty()) {
            try {
                int size = Integer.parseInt(savedMaxHistory);
                maxHistorySize = Math.max(MIN_HISTORY_SIZE, Math.min(MAX_HISTORY_SIZE, size));
            } catch (NumberFormatException e) {
                maxHistorySize = DEFAULT_HISTORY_SIZE;
            }
        }
        
        // 加载自动去重配置
        String savedAutoDedupe = persistence.getString(KEY_AUTO_DEDUPE);
        if (savedAutoDedupe != null && !savedAutoDedupe.isEmpty()) {
            autoDedupe = Boolean.parseBoolean(savedAutoDedupe);
        }
        
        // 加载注入点标记数量配置
        String savedMaxInjectionMarkCount = persistence.getString(KEY_MAX_INJECTION_MARK_COUNT);
        if (savedMaxInjectionMarkCount != null && !savedMaxInjectionMarkCount.isEmpty()) {
            try {
                int count = Integer.parseInt(savedMaxInjectionMarkCount);
                maxInjectionMarkCount = Math.max(MIN_INJECTION_MARK_COUNT, Math.min(MAX_INJECTION_MARK_COUNT, count));
            } catch (NumberFormatException e) {
                maxInjectionMarkCount = DEFAULT_INJECTION_MARK_COUNT;
            }
        }
        
        // 加载二进制报文警告配置
        String savedShowBinaryWarning = persistence.getString(KEY_SHOW_BINARY_WARNING);
        if (savedShowBinaryWarning != null && !savedShowBinaryWarning.isEmpty()) {
            showBinaryWarning = Boolean.parseBoolean(savedShowBinaryWarning);
        }
        
        // 加载扫描配置来源
        String savedConfigSource = persistence.getString(KEY_SCAN_CONFIG_SOURCE);
        if (savedConfigSource != null && !savedConfigSource.isEmpty()) {
            try {
                scanConfigSource = ScanConfigSource.valueOf(savedConfigSource);
            } catch (IllegalArgumentException e) {
                scanConfigSource = ScanConfigSource.DEFAULT;
            }
        }
        
        // 加载选中的常用配置名称
        String savedPresetName = persistence.getString(KEY_SELECTED_PRESET_NAME);
        if (savedPresetName != null && !savedPresetName.isEmpty()) {
            selectedPresetName = savedPresetName;
        }
        
        // ==================== 加载剪贴板功能配置 ====================
        String savedClipboardAutoCopy = persistence.getString(KEY_CLIPBOARD_AUTO_COPY);
        if (savedClipboardAutoCopy != null && !savedClipboardAutoCopy.isEmpty()) {
            clipboardAutoCopy = Boolean.parseBoolean(savedClipboardAutoCopy);
        }
        
        String savedClipboardTempDir = persistence.getString(KEY_CLIPBOARD_TEMP_DIR);
        if (savedClipboardTempDir != null && !savedClipboardTempDir.isEmpty()) {
            clipboardTempDir = savedClipboardTempDir;
        }
        
        // ==================== 加载直接执行功能配置 ====================
        String savedPythonPath = persistence.getString(KEY_DIRECT_PYTHON_PATH);
        if (savedPythonPath != null && !savedPythonPath.isEmpty()) {
            directPythonPath = savedPythonPath;
        }
        
        String savedSqlmapPath = persistence.getString(KEY_DIRECT_SQLMAP_PATH);
        if (savedSqlmapPath != null && !savedSqlmapPath.isEmpty()) {
            directSqlmapPath = savedSqlmapPath;
        }
        
        String savedTerminalType = persistence.getString(KEY_DIRECT_TERMINAL_TYPE);
        if (savedTerminalType != null && !savedTerminalType.isEmpty()) {
            try {
                directTerminalType = TerminalType.valueOf(savedTerminalType);
            } catch (IllegalArgumentException e) {
                directTerminalType = TerminalType.AUTO;
            }
        }
        
        String savedKeepTerminal = persistence.getString(KEY_DIRECT_KEEP_TERMINAL);
        if (savedKeepTerminal != null && !savedKeepTerminal.isEmpty()) {
            directKeepTerminal = Boolean.parseBoolean(savedKeepTerminal);
        }
        
        // ==================== 加载终端窗口标题配置 ====================
        String savedTitleSourceType = persistence.getString(KEY_TITLE_SOURCE_TYPE);
        if (savedTitleSourceType != null && !savedTitleSourceType.isEmpty()) {
            try {
                titleSourceType = TitleSourceType.valueOf(savedTitleSourceType);
            } catch (IllegalArgumentException e) {
                titleSourceType = TitleSourceType.URL_PATH;
            }
        }
        
        String savedTitleFixedValue = persistence.getString(KEY_TITLE_FIXED_VALUE);
        if (savedTitleFixedValue != null && !savedTitleFixedValue.isEmpty()) {
            titleFixedValue = savedTitleFixedValue;
        }
        
        String savedTitlePathSubStart = persistence.getString(KEY_TITLE_PATH_SUB_START);
        if (savedTitlePathSubStart != null && !savedTitlePathSubStart.isEmpty()) {
            titlePathSubStart = savedTitlePathSubStart;
        }
        
        String savedTitlePathSubEnd = persistence.getString(KEY_TITLE_PATH_SUB_END);
        if (savedTitlePathSubEnd != null && !savedTitlePathSubEnd.isEmpty()) {
            titlePathSubEnd = savedTitlePathSubEnd;
        }
        
        String savedTitleRegexPattern = persistence.getString(KEY_TITLE_REGEX_PATTERN);
        if (savedTitleRegexPattern != null && !savedTitleRegexPattern.isEmpty()) {
            titleRegexPattern = savedTitleRegexPattern;
        }
        
        String savedTitleRegexGroup = persistence.getString(KEY_TITLE_REGEX_GROUP);
        if (savedTitleRegexGroup != null && !savedTitleRegexGroup.isEmpty()) {
            try {
                titleRegexGroup = Integer.parseInt(savedTitleRegexGroup);
            } catch (NumberFormatException e) {
                titleRegexGroup = 1;
            }
        }
        
        String savedTitleRegexSource = persistence.getString(KEY_TITLE_REGEX_SOURCE);
        if (savedTitleRegexSource != null && !savedTitleRegexSource.isEmpty()) {
            try {
                titleRegexSource = RegexSource.valueOf(savedTitleRegexSource);
            } catch (IllegalArgumentException e) {
                titleRegexSource = RegexSource.URL;
            }
        }
        
        String savedTitleJsonPath = persistence.getString(KEY_TITLE_JSON_PATH);
        if (savedTitleJsonPath != null && !savedTitleJsonPath.isEmpty()) {
            titleJsonPath = savedTitleJsonPath;
        }
        
        String savedTitleXPath = persistence.getString(KEY_TITLE_XPATH);
        if (savedTitleXPath != null && !savedTitleXPath.isEmpty()) {
            titleXPath = savedTitleXPath;
        }
        
        String savedTitleFormField = persistence.getString(KEY_TITLE_FORM_FIELD);
        if (savedTitleFormField != null && !savedTitleFormField.isEmpty()) {
            titleFormField = savedTitleFormField;
        }
        
        String savedTitleFallback = persistence.getString(KEY_TITLE_FALLBACK);
        if (savedTitleFallback != null && !savedTitleFallback.isEmpty()) {
            titleFallback = savedTitleFallback;
        }
        
        String savedTitleMaxLength = persistence.getString(KEY_TITLE_MAX_LENGTH);
        if (savedTitleMaxLength != null && !savedTitleMaxLength.isEmpty()) {
            try {
                titleMaxLength = Integer.parseInt(savedTitleMaxLength);
            } catch (NumberFormatException e) {
                titleMaxLength = 50;
            }
        }
        
        // 加载标题提取规则列表
        String rulesJson = persistence.getString(KEY_TITLE_RULES);
        if (rulesJson != null && !rulesJson.isEmpty()) {
            try {
                Type listType = new TypeToken<ArrayList<TitleRule>>(){}.getType();
                titleRules = gson.fromJson(rulesJson, listType);
                if (titleRules == null) {
                    titleRules = new ArrayList<>();
                }
            } catch (Exception e) {
                titleRules = new ArrayList<>();
            }
        }
        // 如果规则列表为空，初始化默认规则
        if (titleRules == null || titleRules.isEmpty()) {
            titleRules = new ArrayList<>();
            titleRules.add(TitleRule.createDefaultRule());
            saveTitleRules();
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
        // 更改URL后重置连接状态
        this.connected = false;
    }
    
    // ============ 历史记录数量管理 ============
    
    public int getMaxHistorySize() {
        return maxHistorySize;
    }
    
    public void setMaxHistorySize(int size) {
        this.maxHistorySize = Math.max(MIN_HISTORY_SIZE, Math.min(MAX_HISTORY_SIZE, size));
        persistence.setString(KEY_MAX_HISTORY_SIZE, String.valueOf(this.maxHistorySize));
        // 如果当前历史记录超过新的最大值，则裁剪
        trimHistory();
    }
    
    // ============ 自动去重配置 ============
    
    public boolean isAutoDedupe() {
        return autoDedupe;
    }
    
    public void setAutoDedupe(boolean enabled) {
        this.autoDedupe = enabled;
        persistence.setString(KEY_AUTO_DEDUPE, String.valueOf(enabled));
    }
    
    // ============ 注入点标记数量配置 ============
    
    public int getMaxInjectionMarkCount() {
        return maxInjectionMarkCount;
    }
    
    public void setMaxInjectionMarkCount(int count) {
        this.maxInjectionMarkCount = Math.max(MIN_INJECTION_MARK_COUNT, Math.min(MAX_INJECTION_MARK_COUNT, count));
        persistence.setString(KEY_MAX_INJECTION_MARK_COUNT, String.valueOf(this.maxInjectionMarkCount));
    }
    
    // ============ 二进制报文警告配置 ============
    
    public boolean isShowBinaryWarning() {
        return showBinaryWarning;
    }
    
    public void setShowBinaryWarning(boolean show) {
        this.showBinaryWarning = show;
        persistence.setString(KEY_SHOW_BINARY_WARNING, String.valueOf(show));
    }
    
    // ============ 扫描配置来源管理 ============
    
    public ScanConfigSource getScanConfigSource() {
        return scanConfigSource;
    }
    
    public void setScanConfigSource(ScanConfigSource source) {
        this.scanConfigSource = source;
        persistence.setString(KEY_SCAN_CONFIG_SOURCE, source.name());
    }
    
    public String getSelectedPresetName() {
        return selectedPresetName;
    }
    
    public void setSelectedPresetName(String name) {
        this.selectedPresetName = name;
        if (name != null) {
            persistence.setString(KEY_SELECTED_PRESET_NAME, name);
        }
    }
    
    /**
     * 设置常用配置数据库引用
     */
    public void setPresetDatabase(PresetConfigDatabase database) {
        this.presetDatabase = database;
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
        persistence.setString(KEY_CLIPBOARD_AUTO_COPY, String.valueOf(autoCopy));
    }
    
    /**
     * 获取临时文件目录
     * @return 临时目录路径，空字符串表示使用系统默认
     */
    public String getClipboardTempDir() {
        return clipboardTempDir;
    }
    
    /**
     * 设置临时文件目录
     * @param tempDir 临时目录路径，空字符串表示使用系统默认
     */
    public void setClipboardTempDir(String tempDir) {
        this.clipboardTempDir = tempDir != null ? tempDir : "";
        persistence.setString(KEY_CLIPBOARD_TEMP_DIR, this.clipboardTempDir);
    }
    
    // ============ 直接执行功能配置管理 ============
    
    /**
     * 获取Python解释器路径
     * @return Python路径，空字符串表示使用系统PATH中的python
     */
    public String getDirectPythonPath() {
        return directPythonPath;
    }
    
    /**
     * 设置Python解释器路径
     * @param path Python路径，空字符串表示使用系统PATH中的python
     */
    public void setDirectPythonPath(String path) {
        this.directPythonPath = path != null ? path : "";
        persistence.setString(KEY_DIRECT_PYTHON_PATH, this.directPythonPath);
    }
    
    /**
     * 获取SQLMap脚本路径
     * @return SQLMap路径，空字符串表示需要用户配置
     */
    public String getDirectSqlmapPath() {
        return directSqlmapPath;
    }
    
    /**
     * 设置SQLMap脚本路径
     * @param path SQLMap路径
     */
    public void setDirectSqlmapPath(String path) {
        this.directSqlmapPath = path != null ? path : "";
        persistence.setString(KEY_DIRECT_SQLMAP_PATH, this.directSqlmapPath);
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
        persistence.setString(KEY_DIRECT_TERMINAL_TYPE, this.directTerminalType.name());
    }
    
    /**
     * 获取是否保持终端打开
     */
    public boolean isDirectKeepTerminal() {
        return directKeepTerminal;
    }
    
    /**
     * 设置是否保持终端打开
     */
    public void setDirectKeepTerminal(boolean keepOpen) {
        this.directKeepTerminal = keepOpen;
        persistence.setString(KEY_DIRECT_KEEP_TERMINAL, String.valueOf(keepOpen));
    }
    
    // ============ 终端窗口标题配置管理 ============
    
    /**
     * 获取标题来源类型
     */
    public TitleSourceType getTitleSourceType() {
        return titleSourceType;
    }
    
    /**
     * 设置标题来源类型
     */
    public void setTitleSourceType(TitleSourceType type) {
        this.titleSourceType = type != null ? type : TitleSourceType.URL_PATH;
        persistence.setString(KEY_TITLE_SOURCE_TYPE, this.titleSourceType.name());
    }
    
    /**
     * 获取固定标题值
     */
    public String getTitleFixedValue() {
        return titleFixedValue;
    }
    
    /**
     * 设置固定标题值
     */
    public void setTitleFixedValue(String value) {
        this.titleFixedValue = value != null ? value : "SQLMap";
        persistence.setString(KEY_TITLE_FIXED_VALUE, this.titleFixedValue);
    }
    
    /**
     * 获取URL路径子串起始位置
     */
    public String getTitlePathSubStart() {
        return titlePathSubStart;
    }
    
    /**
     * 设置URL路径子串起始位置
     */
    public void setTitlePathSubStart(String start) {
        this.titlePathSubStart = start != null ? start : "0";
        persistence.setString(KEY_TITLE_PATH_SUB_START, this.titlePathSubStart);
    }
    
    /**
     * 获取URL路径子串结束位置
     */
    public String getTitlePathSubEnd() {
        return titlePathSubEnd;
    }
    
    /**
     * 设置URL路径子串结束位置
     */
    public void setTitlePathSubEnd(String end) {
        this.titlePathSubEnd = end != null ? end : "-0";
        persistence.setString(KEY_TITLE_PATH_SUB_END, this.titlePathSubEnd);
    }
    
    /**
     * 获取正则表达式模式
     */
    public String getTitleRegexPattern() {
        return titleRegexPattern;
    }
    
    /**
     * 设置正则表达式模式
     */
    public void setTitleRegexPattern(String pattern) {
        this.titleRegexPattern = pattern != null ? pattern : "";
        persistence.setString(KEY_TITLE_REGEX_PATTERN, this.titleRegexPattern);
    }
    
    /**
     * 获取正则捕获组索引
     */
    public int getTitleRegexGroup() {
        return titleRegexGroup;
    }
    
    /**
     * 设置正则捕获组索引
     */
    public void setTitleRegexGroup(int group) {
        this.titleRegexGroup = Math.max(0, group);
        persistence.setString(KEY_TITLE_REGEX_GROUP, String.valueOf(this.titleRegexGroup));
    }
    
    /**
     * 获取正则匹配源
     */
    public RegexSource getTitleRegexSource() {
        return titleRegexSource;
    }
    
    /**
     * 设置正则匹配源
     */
    public void setTitleRegexSource(RegexSource source) {
        this.titleRegexSource = source != null ? source : RegexSource.URL;
        persistence.setString(KEY_TITLE_REGEX_SOURCE, this.titleRegexSource.name());
    }
    
    /**
     * 获取JSON Path表达式
     */
    public String getTitleJsonPath() {
        return titleJsonPath;
    }
    
    /**
     * 设置JSON Path表达式
     */
    public void setTitleJsonPath(String jsonPath) {
        this.titleJsonPath = jsonPath != null ? jsonPath : "$.api";
        persistence.setString(KEY_TITLE_JSON_PATH, this.titleJsonPath);
    }
    
    /**
     * 获取XPath表达式
     */
    public String getTitleXPath() {
        return titleXPath;
    }
    
    /**
     * 设置XPath表达式
     */
    public void setTitleXPath(String xpath) {
        this.titleXPath = xpath != null ? xpath : "//method";
        persistence.setString(KEY_TITLE_XPATH, this.titleXPath);
    }
    
    /**
     * 获取表单字段名
     */
    public String getTitleFormField() {
        return titleFormField;
    }
    
    /**
     * 设置表单字段名
     */
    public void setTitleFormField(String field) {
        this.titleFormField = field != null ? field : "action";
        persistence.setString(KEY_TITLE_FORM_FIELD, this.titleFormField);
    }
    
    /**
     * 获取回退标题
     */
    public String getTitleFallback() {
        return titleFallback;
    }
    
    /**
     * 设置回退标题
     */
    public void setTitleFallback(String fallback) {
        this.titleFallback = fallback != null ? fallback : "SQLMap";
        persistence.setString(KEY_TITLE_FALLBACK, this.titleFallback);
    }
    
    /**
     * 获取标题最大长度
     */
    public int getTitleMaxLength() {
        return titleMaxLength;
    }
    
    /**
     * 设置标题最大长度
     */
    public void setTitleMaxLength(int maxLength) {
        this.titleMaxLength = Math.max(1, Math.min(200, maxLength));
        persistence.setString(KEY_TITLE_MAX_LENGTH, String.valueOf(this.titleMaxLength));
    }
    
    /**
     * 获取完整的标题配置对象
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
            titleXPath,
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
    
    // ============ 标题提取规则列表管理 ============
    
    /**
     * 获取所有标题提取规则（按优先级排序）
     */
    public List<TitleRule> getTitleRules() {
        if (titleRules == null) {
            titleRules = new ArrayList<>();
            titleRules.add(TitleRule.createDefaultRule());
        }
        // 返回按优先级排序的副本
        List<TitleRule> sorted = new ArrayList<>(titleRules);
        sorted.sort((a, b) -> Integer.compare(a.getPriority(), b.getPriority()));
        return sorted;
    }
    
    /**
     * 设置标题提取规则列表
     */
    public void setTitleRules(List<TitleRule> rules) {
        if (rules == null) {
            this.titleRules = new ArrayList<>();
        } else {
            this.titleRules = new ArrayList<>(rules);
        }
        saveTitleRules();
    }
    
    /**
     * 保存规则列表到持久化存储
     */
    private void saveTitleRules() {
        if (titleRules == null) return;
        String json = gson.toJson(titleRules);
        persistence.setString(KEY_TITLE_RULES, json);
    }
    
    /**
     * 添加新规则
     */
    public void addTitleRule(TitleRule rule) {
        if (rule == null) return;
        if (titleRules == null) {
            titleRules = new ArrayList<>();
        }
        // 设置优先级为新规则的最大优先级+1
        int maxPriority = 0;
        for (TitleRule r : titleRules) {
            if (r.getPriority() > maxPriority) {
                maxPriority = r.getPriority();
            }
        }
        rule.setPriority(maxPriority + 1);
        titleRules.add(rule);
        saveTitleRules();
    }
    
    /**
     * 更新规则
     */
    public void updateTitleRule(TitleRule rule) {
        if (rule == null || titleRules == null) return;
        for (int i = 0; i < titleRules.size(); i++) {
            if (titleRules.get(i).getId().equals(rule.getId())) {
                rule.touch(); // 更新修改时间
                titleRules.set(i, rule);
                saveTitleRules();
                return;
            }
        }
    }
    
    /**
     * 删除规则（不允许删除默认规则）
     */
    public boolean deleteTitleRule(String ruleId) {
        if (ruleId == null || titleRules == null) return false;
        // 不允许删除默认规则
        if (TitleRule.DEFAULT_RULE_ID.equals(ruleId)) {
            return false;
        }
        for (int i = 0; i < titleRules.size(); i++) {
            if (titleRules.get(i).getId().equals(ruleId)) {
                titleRules.remove(i);
                saveTitleRules();
                return true;
            }
        }
        return false;
    }
    
    /**
     * 获取规则通过ID
     */
    public TitleRule getTitleRuleById(String ruleId) {
        if (ruleId == null || titleRules == null) return null;
        for (TitleRule rule : titleRules) {
            if (rule.getId().equals(ruleId)) {
                return rule;
            }
        }
        return null;
    }
    
    /**
     * 移动规则优先级
     */
    public void moveRulePriority(String ruleId, int newPriority) {
        if (ruleId == null || titleRules == null) return;
        // 默认规则不允许修改优先级
        if (TitleRule.DEFAULT_RULE_ID.equals(ruleId)) return;
        
        TitleRule targetRule = null;
        for (TitleRule rule : titleRules) {
            if (rule.getId().equals(ruleId)) {
                targetRule = rule;
                break;
            }
        }
        if (targetRule == null) return;
        
        // 重新计算优先级
        newPriority = Math.max(1, newPriority); // 其他规则最低优先级为1
        
        // 调整其他规则的优先级
        for (TitleRule rule : titleRules) {
            if (rule.getId().equals(ruleId)) continue;
            if (rule.getPriority() >= newPriority && rule.getPriority() < targetRule.getPriority()) {
                rule.setPriority(rule.getPriority() + 1);
            } else if (rule.getPriority() <= newPriority && rule.getPriority() > targetRule.getPriority()) {
                rule.setPriority(rule.getPriority() - 1);
            }
        }
        targetRule.setPriority(newPriority);
        targetRule.touch();
        saveTitleRules();
    }
    
    /**
     * 上移规则（优先级降低）
     */
    public void moveRuleUp(String ruleId) {
        if (ruleId == null || titleRules == null) return;
        if (TitleRule.DEFAULT_RULE_ID.equals(ruleId)) return;
        
        List<TitleRule> sorted = getTitleRules();
        int index = -1;
        for (int i = 0; i < sorted.size(); i++) {
            if (sorted.get(i).getId().equals(ruleId)) {
                index = i;
                break;
            }
        }
        if (index <= 1) return; // 已经是第一个（默认规则在位置0）
        
        // 交换优先级
        TitleRule current = sorted.get(index);
        TitleRule prev = sorted.get(index - 1);
        int tempPriority = current.getPriority();
        current.setPriority(prev.getPriority());
        prev.setPriority(tempPriority);
        current.touch();
        prev.touch();
        saveTitleRules();
    }
    
    /**
     * 下移规则（优先级提高）
     */
    public void moveRuleDown(String ruleId) {
        if (ruleId == null || titleRules == null) return;
        if (TitleRule.DEFAULT_RULE_ID.equals(ruleId)) return;
        
        List<TitleRule> sorted = getTitleRules();
        int index = -1;
        for (int i = 0; i < sorted.size(); i++) {
            if (sorted.get(i).getId().equals(ruleId)) {
                index = i;
                break;
            }
        }
        if (index < 0 || index >= sorted.size() - 1) return;
        
        // 交换优先级
        TitleRule current = sorted.get(index);
        TitleRule next = sorted.get(index + 1);
        int tempPriority = current.getPriority();
        current.setPriority(next.getPriority());
        next.setPriority(tempPriority);
        current.touch();
        next.touch();
        saveTitleRules();
    }
}
