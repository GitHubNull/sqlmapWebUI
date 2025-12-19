package com.sqlmapwebui.burp;

import okhttp3.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * API Client for SQLMap WebUI Backend (Montoya API版本)
 * 
 * 使用OkHttp进行HTTP通信
 */
public class SqlmapApiClient {
    
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final int TIMEOUT_SECONDS = 30;
    
    private String baseUrl;
    private final OkHttpClient client;
    
    public SqlmapApiClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        
        this.client = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build();
    }
    
    /**
     * 获取后端版本信息
     */
    public String getVersion() throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/version")
            .get()
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response code: " + response.code());
            }
            
            ResponseBody body = response.body();
            return body != null ? body.string() : "unknown";
        }
    }
    
    /**
     * 发送扫描任务到后端
     */
    public String sendTask(String jsonPayload) throws IOException {
        RequestBody body = RequestBody.create(jsonPayload, JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/burp/admin/scan")
            .post(body)
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to send task: " + response.code());
            }
            
            ResponseBody responseBody = response.body();
            return responseBody != null ? responseBody.string() : "";
        }
    }
    
    /**
     * 获取基础URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }
    
    /**
     * 设置基础URL
     */
    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }
}
