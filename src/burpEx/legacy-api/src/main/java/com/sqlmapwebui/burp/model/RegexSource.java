package com.sqlmapwebui.burp.model;

/**
 * 正则匹配源枚举
 */
public enum RegexSource {
    URL,           // 匹配 URL
    REQUEST_BODY,  // 匹配请求体
    FULL_REQUEST   // 匹配完整请求
}
