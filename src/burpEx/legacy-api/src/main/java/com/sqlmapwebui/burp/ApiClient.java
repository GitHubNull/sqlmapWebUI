package com.sqlmapwebui.burp;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * API Client for SQLMap WebUI Backend Communication
 * 
 * Handles HTTP requests to the Python backend server.
 */
public class ApiClient {
    
    private final String baseUrl;
    private final OkHttpClient httpClient;
    private final Gson gson;
    
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final int CONNECT_TIMEOUT = 10;
    private static final int READ_TIMEOUT = 30;
    private static final int WRITE_TIMEOUT = 30;
    
    public ApiClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.gson = new Gson();
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
            .build();
    }
    
    /**
     * Get backend version via health check endpoint
     */
    public String getVersion() throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/health")
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response code: " + response.code());
            }
            
            String responseBody = response.body() != null ? response.body().string() : "";
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            
            if (json.has("data") && json.get("data").isJsonObject()) {
                JsonObject data = json.getAsJsonObject("data");
                return data.has("version") ? data.get("version").getAsString() : "unknown";
            }
            return "unknown";
        }
    }
    
    /**
     * Send task to backend
     */
    public String sendTask(String jsonPayload) throws IOException {
        RequestBody body = RequestBody.create(jsonPayload, JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/burpsuite/admin/task/add")
            .post(body)
            .addHeader("Content-Type", "application/json")
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            String responseBody = response.body() != null ? response.body().string() : "";
            
            if (!response.isSuccessful()) {
                throw new IOException("Failed to create task: " + response.code() + " - " + responseBody);
            }
            
            return responseBody;
        }
    }
    
    /**
     * Get task list
     */
    public String getTaskList() throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/burpsuite/admin/task/list")
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response code: " + response.code());
            }
            return response.body() != null ? response.body().string() : "";
        }
    }
    
    /**
     * Stop task by ID
     */
    public String stopTask(String taskId) throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/burpsuite/admin/task/stop?taskId=" + taskId)
            .put(RequestBody.create("", JSON))
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response code: " + response.code());
            }
            return response.body() != null ? response.body().string() : "";
        }
    }
    
    /**
     * Delete task by ID
     */
    public String deleteTask(String taskId) throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/burpsuite/admin/task/delete?taskId=" + taskId)
            .delete()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response code: " + response.code());
            }
            return response.body() != null ? response.body().string() : "";
        }
    }
    
    /**
     * Get task logs
     */
    public String getTaskLogs(String taskId) throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/burpsuite/admin/task/logs/getLogsByTaskId?taskId=" + taskId)
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response code: " + response.code());
            }
            return response.body() != null ? response.body().string() : "";
        }
    }
    
    /**
     * 获取临时目录配置
     */
    public String getTempDirConfig() throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/api/config/temp-dir")
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get temp dir config: " + response.code());
            }
            return response.body() != null ? response.body().string() : "";
        }
    }
    
    /**
     * 设置临时目录配置
     */
    public String setTempDirConfig(String tempDir) throws IOException {
        JsonObject json = new JsonObject();
        json.addProperty("tempDir", tempDir);
        
        RequestBody body = RequestBody.create(json.toString(), JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/config/temp-dir")
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to set temp dir config: " + response.code());
            }
            return response.body() != null ? response.body().string() : "";
        }
    }
    
    /**
     * 重置临时目录为默认值
     */
    public String resetTempDirConfig() throws IOException {
        RequestBody body = RequestBody.create("{}", JSON);
        
        Request request = new Request.Builder()
            .url(baseUrl + "/api/config/temp-dir/reset")
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to reset temp dir config: " + response.code());
            }
            return response.body() != null ? response.body().string() : "";
        }
    }
}
