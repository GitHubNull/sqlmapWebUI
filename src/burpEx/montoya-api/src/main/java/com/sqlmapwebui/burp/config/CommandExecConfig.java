package com.sqlmapwebui.burp.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sqlmapwebui.burp.model.TitleRule;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

/**
 * 命令行执行配置数据模型
 * 存储剪贴板复制和直接执行的共用配置
 */
public class CommandExecConfig {

    private boolean autoCopy = true;            // 自动复制到剪贴板
    private String tempDir = "";                // HTTP请求临时存储目录
    private String scriptTempDir = "";          // 临时执行脚本存储目录
    private String pythonPath = "";             // Python解释器路径
    private String sqlmapPath = "";             // SQLMap脚本路径
    private String terminalType = "AUTO";       // 终端类型
    private boolean keepTerminal = true;        // 执行后保持终端打开
    private List<TitleRule> titleRules = new ArrayList<>();  // 标题提取规则
    private String titleFallback = "SQLMap";    // 回退标题
    private int titleMaxLength = 50;            // 标题最大长度

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    /**
     * 创建默认配置
     */
    public static CommandExecConfig createDefault() {
        CommandExecConfig config = new CommandExecConfig();
        config.setAutoCopy(true);
        config.setTempDir("");
        config.setPythonPath("");
        config.setSqlmapPath("");
        config.setTerminalType("AUTO");
        config.setKeepTerminal(true);
        config.setTitleRules(new ArrayList<>());
        config.setTitleFallback("SQLMap");
        config.setTitleMaxLength(50);
        return config;
    }

    /**
     * 从JSON字符串解析配置
     */
    public static CommandExecConfig fromJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return createDefault();
        }
        try {
            CommandExecConfig config = GSON.fromJson(json, CommandExecConfig.class);
            if (config == null) {
                return createDefault();
            }
            // 确保 titleRules 不为 null
            if (config.getTitleRules() == null) {
                config.setTitleRules(new ArrayList<>());
            }
            return config;
        } catch (Exception e) {
            return createDefault();
        }
    }

    /**
     * 转换为JSON字符串
     */
    public String toJson() {
        return GSON.toJson(this);
    }

    /**
     * 从标题规则JSON解析
     */
    public static List<TitleRule> parseTitleRules(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new ArrayList<>();
        }
        try {
            Type listType = new TypeToken<ArrayList<TitleRule>>(){}.getType();
            List<TitleRule> rules = GSON.fromJson(json, listType);
            return rules != null ? rules : new ArrayList<>();
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    /**
     * 将标题规则转换为JSON
     */
    public static String titleRulesToJson(List<TitleRule> rules) {
        if (rules == null) {
            return "[]";
        }
        return GSON.toJson(rules);
    }

    // ==================== Getters and Setters ====================

    public boolean isAutoCopy() {
        return autoCopy;
    }

    public void setAutoCopy(boolean autoCopy) {
        this.autoCopy = autoCopy;
    }

    public String getTempDir() {
        return tempDir != null ? tempDir : "";
    }

    public void setTempDir(String tempDir) {
        this.tempDir = tempDir != null ? tempDir : "";
    }

    public String getScriptTempDir() {
        return scriptTempDir != null ? scriptTempDir : "";
    }

    public void setScriptTempDir(String scriptTempDir) {
        this.scriptTempDir = scriptTempDir != null ? scriptTempDir : "";
    }

    public String getPythonPath() {
        return pythonPath != null ? pythonPath : "";
    }

    public void setPythonPath(String pythonPath) {
        this.pythonPath = pythonPath != null ? pythonPath : "";
    }

    public String getSqlmapPath() {
        return sqlmapPath != null ? sqlmapPath : "";
    }

    public void setSqlmapPath(String sqlmapPath) {
        this.sqlmapPath = sqlmapPath != null ? sqlmapPath : "";
    }

    public String getTerminalType() {
        return terminalType != null ? terminalType : "AUTO";
    }

    public void setTerminalType(String terminalType) {
        this.terminalType = terminalType != null ? terminalType : "AUTO";
    }

    public boolean isKeepTerminal() {
        return keepTerminal;
    }

    public void setKeepTerminal(boolean keepTerminal) {
        this.keepTerminal = keepTerminal;
    }

    public List<TitleRule> getTitleRules() {
        return titleRules != null ? titleRules : new ArrayList<>();
    }

    public void setTitleRules(List<TitleRule> titleRules) {
        this.titleRules = titleRules != null ? titleRules : new ArrayList<>();
    }

    public String getTitleFallback() {
        return titleFallback != null ? titleFallback : "SQLMap";
    }

    public void setTitleFallback(String titleFallback) {
        this.titleFallback = titleFallback != null ? titleFallback : "SQLMap";
    }

    public int getTitleMaxLength() {
        return titleMaxLength > 0 ? titleMaxLength : 50;
    }

    public void setTitleMaxLength(int titleMaxLength) {
        this.titleMaxLength = titleMaxLength > 0 ? titleMaxLength : 50;
    }

    @Override
    public String toString() {
        return "CommandExecConfig{" +
                "autoCopy=" + autoCopy +
                ", tempDir='" + tempDir + '\'' +
                ", scriptTempDir='" + scriptTempDir + '\'' +
                ", pythonPath='" + pythonPath + '\'' +
                ", sqlmapPath='" + sqlmapPath + '\'' +
                ", terminalType='" + terminalType + '\'' +
                ", keepTerminal=" + keepTerminal +
                ", titleRulesCount=" + (titleRules != null ? titleRules.size() : 0) +
                ", titleFallback='" + titleFallback + '\'' +
                ", titleMaxLength=" + titleMaxLength +
                '}';
    }
}
