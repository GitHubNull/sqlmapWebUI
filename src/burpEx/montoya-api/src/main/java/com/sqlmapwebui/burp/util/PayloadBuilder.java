package com.sqlmapwebui.burp.util;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.util.List;
import java.util.Map;

/**
 * HTTP 请求 Payload 构建器
 * 使用 Gson 统一处理 JSON 序列化，替代手动拼接
 * 
 * 注意：此类使用 Java 17 语法
 */
public final class PayloadBuilder {
    
    private static final Gson GSON = new Gson();
    
    private PayloadBuilder() {
        throw new AssertionError("PayloadBuilder cannot be instantiated");
    }
    
    /**
     * 构建任务 Payload
     * 
     * @param scanUrl 扫描 URL
     * @param host 主机
     * @param method HTTP 方法
     * @param headers Headers 列表
     * @param body 请求体
     * @param options 扫描选项
     * @return JSON 字符串
     */
    public static String buildTaskPayload(
            String scanUrl,
            String host,
            String method,
            List<String> headers,
            String body,
            Map<String, Object> options) {
        
        JsonObject payload = new JsonObject();
        payload.addProperty("scanUrl", scanUrl);
        payload.addProperty("host", host);
        payload.addProperty("method", method);
        payload.add("headers", GSON.toJsonTree(headers));
        payload.addProperty("body", body);
        payload.add("options", GSON.toJsonTree(options));
        
        return GSON.toJson(payload);
    }
}
