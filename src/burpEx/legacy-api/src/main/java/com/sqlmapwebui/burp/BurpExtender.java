package com.sqlmapwebui.burp;

import burp.*;

import com.sqlmapwebui.burp.dialogs.*;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * SQLMap WebUI Burp Extension - Legacy API Implementation
 * 
 * 功能：
 * 1. 提交扫描任务
 * 2. 配置默认扫描配置和常用扫描配置
 * 3. 提交时选择配置（默认/常用/历史）
 * 4. 标记注入点扫描
 * 5. 提交会话Header
 * 6. 提交Header规则
 * 
 * 批量选择时自动过滤二进制内容的报文，只有纯文本请求才会被发送
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // 配置管理器
    private ConfigManager configManager;
    private SqlmapApiClient apiClient;
    
    // UI Components
    private SqlmapUITab uiTab;
    
    private static final String EXTENSION_NAME = "SQLMap WebUI";
    private static final String EXTENSION_VERSION = "1.0.0";
    
    /**
     * 过滤结果类 - 存储过滤后的纯文本请求和过滤统计
     */
    private static class FilterResult {
        final List<IHttpRequestResponse> textMessages;
        final List<IHttpRequestResponse> binaryMessages;
        
        FilterResult(List<IHttpRequestResponse> textMessages, List<IHttpRequestResponse> binaryMessages) {
            this.textMessages = textMessages;
            this.binaryMessages = binaryMessages;
        }
        
        int totalCount() {
            return textMessages.size() + binaryMessages.size();
        }
        
        int textCount() {
            return textMessages.size();
        }
        
        int binaryCount() {
            return binaryMessages.size();
        }
        
        boolean hasTextMessages() {
            return !textMessages.isEmpty();
        }
        
        boolean allBinary() {
            return textMessages.isEmpty() && !binaryMessages.isEmpty();
        }
        
        String getMenuSuffix() {
            if (totalCount() == 1) {
                return binaryMessages.isEmpty() ? "" : " (二进制报文)";
            } else {
                return String.format(" [%d/%d 可扫描]", textCount(), totalCount());
            }
        }
    }
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // 初始化配置管理器
        this.configManager = new ConfigManager(callbacks);
        
        // 初始化API客户端
        this.apiClient = new SqlmapApiClient();
        this.apiClient.setBaseUrl(configManager.getBackendUrl());
        
        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME + " v" + EXTENSION_VERSION + " (Legacy)");
        
        // Register context menu factory
        callbacks.registerContextMenuFactory(this);
        
        // Initialize UI
        SwingUtilities.invokeLater(() -> {
            uiTab = new SqlmapUITab(callbacks, apiClient, configManager, this::onBackendUrlChange);
        });
        
        // Add tab to Burp Suite
        callbacks.addSuiteTab(this);
        
        stdout.println("[+] " + EXTENSION_NAME + " v" + EXTENSION_VERSION + " (Legacy API) loaded successfully!");
        stdout.println("[+] Backend URL: " + configManager.getBackendUrl());
        stdout.println("[+] 功能: 提交扫描任务、配置管理");
        stdout.println("[+] 右键菜单: Send to SQLMap WebUI / Send to SQLMap WebUI (配置扫描)...");
    }
    
    /**
     * 后端URL变更回调
     */
    private void onBackendUrlChange(String newUrl) {
        apiClient.setBaseUrl(newUrl);
        stdout.println("[+] Backend URL updated to: " + newUrl);
    }
    
    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }
    
    @Override
    public Component getUiComponent() {
        if (uiTab == null) {
            uiTab = new SqlmapUITab(callbacks, apiClient, configManager, this::onBackendUrlChange);
        }
        return uiTab;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        // 只有已连接状态才显示菜单
        if (!configManager.isConnected()) {
            return menuItems;
        }
        
        byte invocationContext = invocation.getInvocationContext();
        if (invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
            invocationContext == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            invocationContext == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE ||
            invocationContext == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE) {
            
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages == null || selectedMessages.length == 0) {
                return menuItems;
            }
            
            // 过滤二进制请求
            FilterResult filterResult = filterBinaryRequests(selectedMessages);
            String menuSuffix = filterResult.getMenuSuffix();
            
            // 使用默认配置发送
            JMenuItem sendWithDefault = new JMenuItem("Send to SQLMap WebUI" + menuSuffix);
            if (filterResult.allBinary()) {
                sendWithDefault.setEnabled(false);
                sendWithDefault.setToolTipText("所有选中的报文都是二进制格式，无法发起扫描任务");
            } else {
                sendWithDefault.addActionListener(e -> {
                    sendFilteredRequests(filterResult, configManager.getDefaultConfig());
                });
            }
            menuItems.add(sendWithDefault);
            
            // 标记注入点并扫描 - 支持多选报文
            int maxMarkCount = configManager.getMaxInjectionMarkCount();
            JMenuItem markInjectionPoints = new JMenuItem("标记注入点并扫描 (*)" + menuSuffix);
            if (filterResult.allBinary()) {
                markInjectionPoints.setEnabled(false);
                markInjectionPoints.setToolTipText("所有选中的报文都是二进制格式，无法发起扫描任务");
            } else {
                // 超过限制时显示警告但仍然可点击（对话框会处理超限情况）
                if (filterResult.textCount() > maxMarkCount) {
                    markInjectionPoints.setToolTipText(
                        String.format("选中的纯文本报文数量(%d)超过标记上限(%d)，仅前%d个报文可进行注入点标记", 
                            filterResult.textCount(), maxMarkCount, maxMarkCount));
                }
                markInjectionPoints.addActionListener(e -> {
                    if (filterResult.hasTextMessages()) {
                        BatchInjectionMarkDialog dialog = new BatchInjectionMarkDialog(
                            callbacks, apiClient, configManager, uiTab, helpers);
                        dialog.show(filterResult.textMessages, filterResult.binaryMessages);
                    }
                });
            }
            menuItems.add(markInjectionPoints);
            
            // 配置扫描发送（高级配置对话框）
            JMenuItem sendWithOptions = new JMenuItem("Send to SQLMap WebUI (配置扫描)..." + menuSuffix);
            if (filterResult.allBinary()) {
                sendWithOptions.setEnabled(false);
                sendWithOptions.setToolTipText("所有选中的报文都是二进制格式，无法发起扫描任务");
            } else {
                sendWithOptions.addActionListener(e -> {
                    if (filterResult.hasTextMessages()) {
                        // 使用新的高级配置对话框
                        AdvancedScanConfigDialog dialog = new AdvancedScanConfigDialog(
                            callbacks, apiClient, configManager, uiTab, helpers);
                        dialog.show(filterResult.textMessages, filterResult.binaryMessages);
                    }
                });
            }
            menuItems.add(sendWithOptions);
            
            // 提交会话Header 和 Header规则 - 仅在选中单条请求时显示
            if (selectedMessages.length == 1 && filterResult.hasTextMessages()) {
                JMenuItem submitSessionHeaders = new JMenuItem("提交会话Header");
                submitSessionHeaders.addActionListener(e -> {
                    SessionHeaderDialog dialog = new SessionHeaderDialog(callbacks, apiClient, uiTab);
                    dialog.show(filterResult.textMessages.get(0));
                });
                menuItems.add(submitSessionHeaders);
                
                JMenuItem submitHeaderRule = new JMenuItem("提交Header规则");
                submitHeaderRule.addActionListener(e -> {
                    HeaderRuleDialog dialog = new HeaderRuleDialog(callbacks, apiClient, uiTab);
                    dialog.show(filterResult.textMessages.get(0));
                });
                menuItems.add(submitHeaderRule);
            }
        }
        
        return menuItems;
    }
    
    /**
     * 过滤二进制请求，返回纯文本请求列表和统计信息
     */
    private FilterResult filterBinaryRequests(IHttpRequestResponse[] messages) {
        List<IHttpRequestResponse> textMessages = new ArrayList<>();
        List<IHttpRequestResponse> binaryMessages = new ArrayList<>();
        
        for (IHttpRequestResponse message : messages) {
            if (BinaryContentDetector.isTextRequest(message, helpers)) {
                textMessages.add(message);
            } else {
                binaryMessages.add(message);
            }
        }
        
        return new FilterResult(textMessages, binaryMessages);
    }
    
    /**
     * 发送过滤后的纯文本请求，并记录被过滤的二进制请求日志
     * 第一步：过滤二进制请求
     * 第二步：去重处理（如果开启）
     */
    private void sendFilteredRequests(FilterResult filterResult, ScanConfig config) {
        // 第一步：记录二进制过滤统计
        if (filterResult.binaryCount() > 0) {
            uiTab.appendLog(String.format("[*] 二进制过滤: %d 个请求已跳过", filterResult.binaryCount()));
            
            // 记录被过滤的二进制请求URL
            for (IHttpRequestResponse binaryMsg : filterResult.binaryMessages) {
                IRequestInfo reqInfo = helpers.analyzeRequest(binaryMsg);
                String url = reqInfo.getUrl().toString();
                BinaryContentDetector.DetectionResult detection = BinaryContentDetector.detect(binaryMsg, helpers);
                uiTab.appendLog(String.format("    [跳过-二进制] %s (原因: %s)", url, detection.getReason()));
            }
        }
        
        // 第二步：去重处理
        List<IHttpRequestResponse> messagesToSend = filterResult.textMessages;
        int duplicateCount = 0;
        
        if (configManager.isAutoDedupe() && messagesToSend.size() > 1) {
            RequestDeduplicator.DedupeResult dedupeResult = RequestDeduplicator.deduplicate(messagesToSend, helpers);
            
            if (dedupeResult.hasDuplicates()) {
                duplicateCount = dedupeResult.duplicateCount();
                uiTab.appendLog(String.format("[*] 重复过滤: %d 个重复请求已跳过", duplicateCount));
                
                // 记录被过滤的重复请求
                for (IHttpRequestResponse dupMsg : dedupeResult.getDuplicateMessages()) {
                    String desc = RequestDeduplicator.getRequestDescription(dupMsg, helpers);
                    uiTab.appendLog(String.format("    [跳过-重复] %s", desc));
                }
                
                messagesToSend = dedupeResult.getUniqueMessages();
            }
        }
        
        // 输出统计汇总
        if (filterResult.binaryCount() > 0 || duplicateCount > 0) {
            uiTab.appendLog(String.format("[*] 最终统计: 共选中 %d 个请求，实际发送 %d 个",
                filterResult.totalCount(), messagesToSend.size()));
        }
        
        // 发送纯文本请求
        for (IHttpRequestResponse message : messagesToSend) {
            sendRequestToBackend(message, config);
        }
    }
    
    /**
     * 发送请求到后端 - 使用默认配置发送
     */
    private void sendRequestToBackend(IHttpRequestResponse requestResponse, ScanConfig config) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            byte[] request = requestResponse.getRequest();
            
            String url = requestInfo.getUrl().toString();
            List<String> headers = requestInfo.getHeaders();
            
            int bodyOffset = requestInfo.getBodyOffset();
            String body = "";
            if (bodyOffset < request.length) {
                body = new String(request, bodyOffset, request.length - bodyOffset);
            }
            
            StringBuilder headersJson = new StringBuilder("[");
            for (int i = 0; i < headers.size(); i++) {
                headersJson.append("\"").append(JsonUtils.escapeJson(headers.get(i))).append("\"");
                if (i < headers.size() - 1) headersJson.append(",");
            }
            headersJson.append("]");
            
            Map<String, Object> options = config.toOptionsMap();
            StringBuilder optionsJson = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : options.entrySet()) {
                if (!first) optionsJson.append(",");
                first = false;
                optionsJson.append("\"").append(entry.getKey()).append("\":");
                if (entry.getValue() instanceof String) {
                    optionsJson.append("\"").append(JsonUtils.escapeJson((String)entry.getValue())).append("\"");
                } else if (entry.getValue() instanceof Boolean) {
                    optionsJson.append(entry.getValue());
                } else {
                    optionsJson.append(entry.getValue());
                }
            }
            optionsJson.append("}");
            
            String jsonPayload = String.format(
                "{\"scanUrl\":\"%s\",\"host\":\"%s\",\"headers\":%s,\"body\":\"%s\",\"options\":%s}",
                JsonUtils.escapeJson(url),
                JsonUtils.escapeJson(requestInfo.getUrl().getHost()),
                headersJson.toString(),
                JsonUtils.escapeJson(body),
                optionsJson.toString()
            );
            
            new Thread(() -> {
                try {
                    String response = apiClient.sendTask(jsonPayload);
                    
                    configManager.addToHistory(config);
                    
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 请求已发送: " + url);
                        uiTab.appendLog("    使用配置: " + config.getName());
                        uiTab.appendLog("    响应: " + response);
                        uiTab.refreshHistoryTable();
                    });
                    
                    stdout.println("[+] Task created for: " + url);
                    
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[-] 发送请求失败: " + e.getMessage());
                    });
                    stderr.println("[-] Error: " + e.getMessage());
                }
            }).start();
            
        } catch (Exception e) {
            uiTab.appendLog("[-] 处理请求失败: " + e.getMessage());
            stderr.println("[-] Error: " + e.getMessage());
        }
    }
}
