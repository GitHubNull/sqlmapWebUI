package com.sqlmapwebui.burp;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
     * 获取后端版本信息 (via health check endpoint)
     */
    public String getVersion() throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/health")
            .get()
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response code: " + response.code());
            }
            
            ResponseBody body = response.body();
            String responseBody = body != null ? body.string() : "";
            
            // 解析JSON获取版本号
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            if (json.has("data") && json.get("data").isJsonObject()) {
                JsonObject data = json.getAsJsonObject("data");
                return data.has("version") ? data.get("version").getAsString() : "unknown";
            }
            return "unknown";
        }
    }
    
    /**
     * 发送扫描任务到后端
     */
    public String sendTask(String jsonPayload) throws IOException {
        RequestBody body = RequestBody.create(jsonPayload, JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/burpsuite/admin/task/add")
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
     * 获取临时目录配置
     * @return JSON字符串，包含currentTempDir, defaultTempDir, isCustom
     */
    public String getTempDirConfig() throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/config/temp-dir")
            .get()
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get temp dir config: " + response.code());
            }
            
            ResponseBody body = response.body();
            return body != null ? body.string() : "";
        }
    }
    
    /**
     * 设置临时目录配置
     * @param tempDir 临时目录路径，为null或空则恢复默认
     * @return JSON响应字符串
     */
    public String setTempDirConfig(String tempDir) throws IOException {
        JsonObject json = new JsonObject();
        json.addProperty("tempDir", tempDir);
        
        RequestBody body = RequestBody.create(json.toString(), JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/config/temp-dir")
            .post(body)
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to set temp dir config: " + response.code());
            }
            
            ResponseBody responseBody = response.body();
            return responseBody != null ? responseBody.string() : "";
        }
    }
    
    /**
     * 重置临时目录为默认值
     * @return JSON响应字符串
     */
    public String resetTempDirConfig() throws IOException {
        RequestBody body = RequestBody.create("{}", JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/config/temp-dir/reset")
            .post(body)
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to reset temp dir config: " + response.code());
            }
            
            ResponseBody responseBody = response.body();
            return responseBody != null ? responseBody.string() : "";
        }
    }
    
    /**
     * 提交会话Header到后端
     * @param jsonPayload JSON格式的会话Header数据
     * @return 响应字符串
     */
    public String sendSessionHeaders(String jsonPayload) throws IOException {
        RequestBody body = RequestBody.create(jsonPayload, JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/commonApi/header/session-headers")
            .post(body)
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to send session headers: " + response.code());
            }
            
            ResponseBody responseBody = response.body();
            return responseBody != null ? responseBody.string() : "";
        }
    }
    
    /**
     * 提交持久化Header规则到后端
     * @param jsonPayload JSON格式的Header规则数据
     * @return 响应字符串
     */
    public String sendHeaderRule(String jsonPayload) throws IOException {
        RequestBody body = RequestBody.create(jsonPayload, JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/commonApi/header/persistent-header-rules")
            .post(body)
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to send header rule: " + response.code());
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
