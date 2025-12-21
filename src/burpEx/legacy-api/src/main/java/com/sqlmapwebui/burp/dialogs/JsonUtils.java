package com.sqlmapwebui.burp.dialogs;

/**
 * JSON工具类
 */
public class JsonUtils {
    
    /**
     * 转义JSON特殊字符
     */
    public static String escapeJson(String text) {
        if (text == null) return "";
        return text
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
}
