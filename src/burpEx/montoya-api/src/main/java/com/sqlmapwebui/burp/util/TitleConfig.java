package com.sqlmapwebui.burp.util;

import com.sqlmapwebui.burp.util.RegexSource;
import com.sqlmapwebui.burp.util.TitleSourceType;

/**
 * 终端窗口标题配置数据类
 * 用于封装标题提取的所有配置参数
 */
public class TitleConfig {
    
    private final TitleSourceType sourceType;
    private final String fixedValue;
    private final String pathSubStart;
    private final String pathSubEnd;
    private final String regexPattern;
    private final int regexGroup;
    private final RegexSource regexSource;
    private final String jsonPath;
    private final String xpath;
    private final String formField;
    private final String fallback;
    private final int maxLength;
    
    /**
     * 创建默认配置
     */
    public TitleConfig() {
        this.sourceType = TitleSourceType.URL_PATH;
        this.fixedValue = "SQLMap";
        this.pathSubStart = "0";
        this.pathSubEnd = "-0";
        this.regexPattern = "";
        this.regexGroup = 1;
        this.regexSource = RegexSource.URL;
        this.jsonPath = "$.api";
        this.xpath = "//method";
        this.formField = "action";
        this.fallback = "SQLMap";
        this.maxLength = 50;
    }
    
    /**
     * 完整构造函数
     */
    public TitleConfig(
            TitleSourceType sourceType,
            String fixedValue,
            String pathSubStart,
            String pathSubEnd,
            String regexPattern,
            int regexGroup,
            RegexSource regexSource,
            String jsonPath,
            String xpath,
            String formField,
            String fallback,
            int maxLength) {
        this.sourceType = sourceType != null ? sourceType : TitleSourceType.URL_PATH;
        this.fixedValue = fixedValue != null ? fixedValue : "SQLMap";
        this.pathSubStart = pathSubStart != null ? pathSubStart : "0";
        this.pathSubEnd = pathSubEnd != null ? pathSubEnd : "-0";
        this.regexPattern = regexPattern != null ? regexPattern : "";
        this.regexGroup = Math.max(0, regexGroup);
        this.regexSource = regexSource != null ? regexSource : RegexSource.URL;
        this.jsonPath = jsonPath != null ? jsonPath : "$.api";
        this.xpath = xpath != null ? xpath : "//method";
        this.formField = formField != null ? formField : "action";
        this.fallback = fallback != null ? fallback : "SQLMap";
        this.maxLength = Math.max(1, Math.min(200, maxLength));
    }
    
    // ============ Getters ============
    
    public TitleSourceType getSourceType() {
        return sourceType;
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
    
    public String getFallback() {
        return fallback;
    }
    
    public int getMaxLength() {
        return maxLength;
    }
    
    // ============ 便捷方法 ============
    
    /**
     * 判断是否使用URL路径作为标题
     */
    public boolean isUrlPathMode() {
        return sourceType == TitleSourceType.URL_PATH;
    }
    
    /**
     * 判断是否使用URL路径子串作为标题
     */
    public boolean isUrlPathSubMode() {
        return sourceType == TitleSourceType.URL_PATH_SUB;
    }
    
    /**
     * 判断是否使用固定标题
     */
    public boolean isFixedMode() {
        return sourceType == TitleSourceType.FIXED;
    }
    
    /**
     * 判断是否使用正则表达式提取
     */
    public boolean isRegexMode() {
        return sourceType == TitleSourceType.REGEX;
    }
    
    /**
     * 判断是否使用JSON Path提取
     */
    public boolean isJsonPathMode() {
        return sourceType == TitleSourceType.JSON_PATH;
    }
    
    /**
     * 判断是否使用XPath提取
     */
    public boolean isXPathMode() {
        return sourceType == TitleSourceType.XPATH;
    }
    
    /**
     * 判断是否使用表单字段提取
     */
    public boolean isFormFieldMode() {
        return sourceType == TitleSourceType.FORM_FIELD;
    }
    
    /**
     * 解析路径子串起始位置
     * @return 解析后的整数，如果解析失败返回0
     */
    public int parsePathSubStart() {
        try {
            return Integer.parseInt(pathSubStart.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    /**
     * 解析路径子串结束位置
     * 特殊值 "-0" 表示到字符串结尾，返回 Integer.MIN_VALUE 作为标记
     * @return 解析后的整数，如果解析失败返回 Integer.MIN_VALUE（表示到结尾）
     */
    public int parsePathSubEnd() {
        String trimmed = pathSubEnd.trim();
        if ("-0".equals(trimmed)) {
            return Integer.MIN_VALUE; // 特殊标记，表示到结尾
        }
        try {
            return Integer.parseInt(trimmed);
        } catch (NumberFormatException e) {
            return Integer.MIN_VALUE;
        }
    }
    
    @Override
    public String toString() {
        return "TitleConfig{" +
                "sourceType=" + sourceType +
                ", fixedValue='" + fixedValue + '\'' +
                ", pathSubStart='" + pathSubStart + '\'' +
                ", pathSubEnd='" + pathSubEnd + '\'' +
                ", regexPattern='" + regexPattern + '\'' +
                ", regexGroup=" + regexGroup +
                ", regexSource=" + regexSource +
                ", jsonPath='" + jsonPath + '\'' +
                ", xpath='" + xpath + '\'' +
                ", formField='" + formField + '\'' +
                ", fallback='" + fallback + '\'' +
                ", maxLength=" + maxLength +
                '}';
    }
}
