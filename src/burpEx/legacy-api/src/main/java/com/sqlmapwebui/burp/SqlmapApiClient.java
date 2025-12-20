package com.sqlmapwebui.burp;

import java.io.IOException;

/**
 * SqlmapApiClient包装类
 * 对ApiClient的包装，使面板代码能与montoya-api保持一致
 */
public class SqlmapApiClient {
    
    private ApiClient apiClient;
    private String baseUrl = "http://localhost:5000";
    
    public SqlmapApiClient() {
        this.apiClient = new ApiClient(baseUrl);
    }
    
    public void setBaseUrl(String url) {
        this.baseUrl = url;
        this.apiClient = new ApiClient(url);
    }
    
    public String getBaseUrl() {
        return baseUrl;
    }
    
    /**
     * 获取后端版本
     */
    public String getVersion() throws IOException {
        return apiClient.getVersion();
    }
    
    /**
     * 发送扫描任务
     */
    public String sendTask(String jsonPayload) throws IOException {
        return apiClient.sendTask(jsonPayload);
    }
    
    /**
     * 获取任务列表
     */
    public String getTaskList() throws IOException {
        return apiClient.getTaskList();
    }
    
    /**
     * 停止任务
     */
    public String stopTask(String taskId) throws IOException {
        return apiClient.stopTask(taskId);
    }
    
    /**
     * 删除任务
     */
    public String deleteTask(String taskId) throws IOException {
        return apiClient.deleteTask(taskId);
    }
    
    /**
     * 获取任务日志
     */
    public String getTaskLogs(String taskId) throws IOException {
        return apiClient.getTaskLogs(taskId);
    }
    
    /**
     * 获取临时目录配置
     */
    public String getTempDirConfig() throws IOException {
        return apiClient.getTempDirConfig();
    }
    
    /**
     * 设置临时目录配置
     */
    public String setTempDirConfig(String tempDir) throws IOException {
        return apiClient.setTempDirConfig(tempDir);
    }
    
    /**
     * 重置临时目录为默认值
     */
    public String resetTempDirConfig() throws IOException {
        return apiClient.resetTempDirConfig();
    }
}
