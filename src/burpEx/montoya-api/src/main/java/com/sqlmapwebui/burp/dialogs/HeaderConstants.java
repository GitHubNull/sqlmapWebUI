package com.sqlmapwebui.burp.dialogs;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Header相关常量
 */
public class HeaderConstants {
    
    /**
     * 常见的会话相关Header名称（不区分大小写匹配）
     */
    public static final Set<String> COMMON_SESSION_HEADERS = new HashSet<>(Arrays.asList(
        "cookie", "authorization", "x-auth-token", "x-access-token", "x-api-key",
        "x-csrf-token", "x-xsrf-token", "session-token", "bearer", "token",
        "x-session-id", "x-session-token", "x-user-token", "x-request-id",
        "x-correlation-id", "x-trace-id"
    ));
    
    /**
     * 判断是否为常见会话Header
     */
    public static boolean isCommonSessionHeader(String headerName) {
        return headerName != null && COMMON_SESSION_HEADERS.contains(headerName.toLowerCase());
    }
}
