package com.sqlmapwebui.burp.model;

/**
 * 终端窗口标题来源类型枚举
 */
public enum TitleSourceType {
    URL_PATH,      // 默认：从 URL 路径提取
    URL_PATH_SUB,  // 从 URL 路径提取子串
    FIXED,         // 固定字符串
    REGEX,         // 正则表达式
    JSON_PATH,     // JSON Path 表达式
    XPATH,         // XPath 表达式
    FORM_FIELD     // 表单字段
}
