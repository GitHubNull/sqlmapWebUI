package com.sqlmapwebui.burp.model;

import java.util.UUID;

/**
 * 标题提取规则数据类
 * 每条规则独立配置，有自己的名称、类型、参数、优先级
 */
public class TitleRule {

    // 默认规则的固定ID
    public static final String DEFAULT_RULE_ID = "default-url-path";

    // 基本属性
    private String id;                    // 唯一标识 (UUID)
    private String name;                  // 规则名称 (如 "提取用户ID")
    private TitleSourceType sourceType;   // 提取类型
    private boolean enabled;              // 是否启用
    private int priority;                 // 优先级 (0最高，数字越大越低)

    // 各类型对应的参数 (根据sourceType使用)
    private String fixedValue;            // FIXED 固定值
    private String pathSubStart;          // URL_PATH_SUB 起始位置
    private String pathSubEnd;            // URL_PATH_SUB 结束位置
    private String regexPattern;          // REGEX 正则表达式
    private int regexGroup;               // REGEX 捕获组
    private RegexSource regexSource;      // REGEX 匹配来源
    private String jsonPath;              // JSON_PATH 表达式
    private String xpath;                 // XPATH 表达式
    private String formField;             // FORM_FIELD 字段名

    // 元数据
    private long createdTime;             // 添加时间 (时间戳)
    private long modifiedTime;            // 最后修改时间
    private String remark;                // 备注

    /**
     * 默认构造器 (用于JSON反序列化)
     */
    public TitleRule() {
        this.id = UUID.randomUUID().toString();
        this.sourceType = TitleSourceType.URL_PATH;
        this.enabled = true;
        this.priority = 999;
        this.regexGroup = 1;
        this.regexSource = RegexSource.URL;
        this.createdTime = System.currentTimeMillis();
        this.modifiedTime = this.createdTime;
    }

    /**
     * 完整构造器
     */
    public TitleRule(String id, String name, TitleSourceType sourceType, boolean enabled,
                     int priority, String fixedValue, String pathSubStart, String pathSubEnd,
                     String regexPattern, int regexGroup, RegexSource regexSource,
                     String jsonPath, String xpath, String formField,
                     long createdTime, long modifiedTime, String remark) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.name = name;
        this.sourceType = sourceType != null ? sourceType : TitleSourceType.URL_PATH;
        this.enabled = enabled;
        this.priority = priority;
        this.fixedValue = fixedValue;
        this.pathSubStart = pathSubStart;
        this.pathSubEnd = pathSubEnd;
        this.regexPattern = regexPattern;
        this.regexGroup = regexGroup;
        this.regexSource = regexSource;
        this.jsonPath = jsonPath;
        this.xpath = xpath;
        this.formField = formField;
        this.createdTime = createdTime > 0 ? createdTime : System.currentTimeMillis();
        this.modifiedTime = modifiedTime > 0 ? modifiedTime : this.createdTime;
        this.remark = remark;
    }

    /**
     * 创建默认规则 (URL路径提取，优先级0)
     */
    public static TitleRule createDefaultRule() {
        return new TitleRule(
            DEFAULT_RULE_ID,
            "URL路径提取",
            TitleSourceType.URL_PATH,
            true,
            0,
            null,
            "0",
            "-0",
            null,
            1,
            RegexSource.URL,
            null,
            null,
            null,
            System.currentTimeMillis(),
            System.currentTimeMillis(),
            "默认规则，提取URL路径最后一段"
        );
    }

    /**
     * 判断是否为默认规则
     */
    public boolean isDefaultRule() {
        return DEFAULT_RULE_ID.equals(this.id);
    }

    /**
     * 获取参数预览字符串 (用于表格显示)
     */
    public String getParamPreview() {
        if (sourceType == null) {
            return "";
        }
        switch (sourceType) {
            case URL_PATH:
                return "(默认)";
            case URL_PATH_SUB:
                return String.format("[%s, %s]",
                    pathSubStart != null ? pathSubStart : "0",
                    pathSubEnd != null ? pathSubEnd : "-0");
            case FIXED:
                return fixedValue != null ? fixedValue : "";
            case REGEX:
                return regexPattern != null ? regexPattern : "";
            case JSON_PATH:
                return jsonPath != null ? jsonPath : "";
            case XPATH:
                return xpath != null ? xpath : "";
            case FORM_FIELD:
                return formField != null ? formField : "";
            default:
                return "";
        }
    }

    // ==================== Getters ====================

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public TitleSourceType getSourceType() {
        return sourceType;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getPriority() {
        return priority;
    }

    public String getFixedValue() {
        return fixedValue;
    }

    public String getPathSubStart() {
        return pathSubStart;
    }

    public String getPathSubEnd() {
        return pathSubEnd;
    }

    public String getRegexPattern() {
        return regexPattern;
    }

    public int getRegexGroup() {
        return regexGroup;
    }

    public RegexSource getRegexSource() {
        return regexSource;
    }

    public String getJsonPath() {
        return jsonPath;
    }

    public String getXpath() {
        return xpath;
    }

    public String getFormField() {
        return formField;
    }

    public long getCreatedTime() {
        return createdTime;
    }

    public long getModifiedTime() {
        return modifiedTime;
    }

    public String getRemark() {
        return remark;
    }

    // ==================== Setters ====================

    public void setId(String id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setSourceType(TitleSourceType sourceType) {
        this.sourceType = sourceType;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public void setFixedValue(String fixedValue) {
        this.fixedValue = fixedValue;
    }

    public void setPathSubStart(String pathSubStart) {
        this.pathSubStart = pathSubStart;
    }

    public void setPathSubEnd(String pathSubEnd) {
        this.pathSubEnd = pathSubEnd;
    }

    public void setRegexPattern(String regexPattern) {
        this.regexPattern = regexPattern;
    }

    public void setRegexGroup(int regexGroup) {
        this.regexGroup = regexGroup;
    }

    public void setRegexSource(RegexSource regexSource) {
        this.regexSource = regexSource;
    }

    public void setJsonPath(String jsonPath) {
        this.jsonPath = jsonPath;
    }

    public void setXpath(String xpath) {
        this.xpath = xpath;
    }

    public void setFormField(String formField) {
        this.formField = formField;
    }

    public void setCreatedTime(long createdTime) {
        this.createdTime = createdTime;
    }

    public void setModifiedTime(long modifiedTime) {
        this.modifiedTime = modifiedTime;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }

    /**
     * 更新修改时间
     */
    public void touch() {
        this.modifiedTime = System.currentTimeMillis();
    }

    @Override
    public String toString() {
        return "TitleRule{" +
            "id='" + id + '\'' +
            ", name='" + name + '\'' +
            ", sourceType=" + sourceType +
            ", enabled=" + enabled +
            ", priority=" + priority +
            '}';
    }
}
