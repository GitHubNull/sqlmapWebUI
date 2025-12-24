package com.sqlmapwebui.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;

import java.nio.charset.StandardCharsets;

/**
 * HTTP请求处理工具类
 * 
 * 解决 Burp Montoya API 默认使用 ISO-8859-1 编码导致的中文乱码问题。
 * 强制使用 UTF-8 编码来正确处理包含中文等非ASCII字符的请求。
 */
public class HttpRequestUtils {
    
    /**
     * 获取请求体内容（UTF-8编码）
     * 
     * 注意：Burp的 request.bodyToString() 可能使用 ISO-8859-1 编码，
     * 导致中文等 UTF-8 字符出现乱码。此方法强制使用 UTF-8 编码。
     * 
     * @param request HTTP请求对象
     * @return UTF-8编码的请求体字符串
     */
    public static String getBodyAsUtf8(HttpRequest request) {
        if (request == null) {
            return "";
        }
        
        try {
            ByteArray body = request.body();
            if (body == null || body.length() == 0) {
                return "";
            }
            
            byte[] bodyBytes = body.getBytes();
            return new String(bodyBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // 如果获取失败，回退到默认方法
            return request.bodyToString();
        }
    }
    
    /**
     * 获取完整的HTTP请求内容（UTF-8编码）
     * 
     * 注意：Burp的 request.toString() 可能使用 ISO-8859-1 编码，
     * 导致中文等 UTF-8 字符出现乱码。此方法强制使用 UTF-8 编码。
     * 
     * @param request HTTP请求对象
     * @return UTF-8编码的完整HTTP请求字符串
     */
    public static String getRequestAsUtf8(HttpRequest request) {
        if (request == null) {
            return "";
        }
        
        try {
            ByteArray requestBytes = request.toByteArray();
            if (requestBytes == null || requestBytes.length() == 0) {
                return "";
            }
            
            byte[] bytes = requestBytes.getBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // 如果获取失败，回退到默认方法
            return request.toString();
        }
    }
}
