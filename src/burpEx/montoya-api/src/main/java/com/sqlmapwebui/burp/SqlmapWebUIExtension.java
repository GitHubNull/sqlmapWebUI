package com.sqlmapwebui.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * SQLMap WebUI Burp Extension - Montoya API Implementation
 * 
 * 功能：
 * 1. 提交扫描任务
 * 2. 配置默认扫描配置和常用扫描配置
 * 3. 提交时选择配置（默认/常用/历史）
 * 
 * 注意：插件端不能管理扫描任务，也不能查看扫描任务记录
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class SqlmapWebUIExtension implements BurpExtension {
    
    private static final String EXTENSION_NAME = "SQLMap WebUI";
    private static final String EXTENSION_VERSION = "1.8.16";
    
    private MontoyaApi api;
    private ConfigManager configManager;
    private SqlmapApiClient apiClient;
    private SqlmapUITab uiTab;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        
        // Set extension name
        api.extension().setName(EXTENSION_NAME + " v" + EXTENSION_VERSION + " (Montoya)");
        
        // 初始化配置管理器
        this.configManager = new ConfigManager(api);
        
        // 初始化API客户端
        this.apiClient = new SqlmapApiClient(configManager.getBackendUrl());
        
        // 创建UI Tab
        this.uiTab = new SqlmapUITab(api, apiClient, configManager, this::onBackendUrlChange);
        
        // 注册UI Tab
        api.userInterface().registerSuiteTab(EXTENSION_NAME, uiTab);
        
        // 注册右键菜单
        SqlmapContextMenuProvider contextMenuProvider = 
            new SqlmapContextMenuProvider(api, apiClient, configManager, uiTab);
        api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);
        
        // 日志输出
        api.logging().logToOutput("[+] " + EXTENSION_NAME + " v" + EXTENSION_VERSION + " (Montoya API) loaded successfully!");
        api.logging().logToOutput("[+] Backend URL: " + configManager.getBackendUrl());
        api.logging().logToOutput("[+] 功能: 提交扫描任务、配置管理");
        api.logging().logToOutput("[+] 右键菜单: Send to SQLMap WebUI / Send to SQLMap WebUI (选择配置)...");
    }
    
    /**
     * 后端URL变更回调
     */
    private void onBackendUrlChange(String newUrl) {
        apiClient.setBaseUrl(newUrl);
        api.logging().logToOutput("[+] Backend URL updated to: " + newUrl);
    }
}
