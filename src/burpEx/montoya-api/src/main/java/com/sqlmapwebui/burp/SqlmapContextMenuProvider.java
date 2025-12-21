package com.sqlmapwebui.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.sqlmapwebui.burp.dialogs.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Context Menu Provider for SQLMap WebUI Extension (Montoya API)
 * 
 * 提供右键菜单：
 * 1. Send to SQLMap WebUI - 使用默认配置发送
 * 2. 标记注入点并扫描 (*) - 手动标记注入点
 * 3. Send to SQLMap WebUI (配置扫描)... - 高级配置发送
 * 4. 提交会话Header - 提交临时会话Header
 * 5. 提交Header规则 - 提交持久化Header规则
 * 
 * 批量选择时自动过滤二进制内容的报文，只有纯文本请求才会被发送
 */
public class SqlmapContextMenuProvider implements ContextMenuItemsProvider {
    
    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final ConfigManager configManager;
    private final SqlmapUITab uiTab;
    
    public SqlmapContextMenuProvider(MontoyaApi api, SqlmapApiClient apiClient, 
                                     ConfigManager configManager, SqlmapUITab uiTab) {
        this.api = api;
        this.apiClient = apiClient;
        this.configManager = configManager;
        this.uiTab = uiTab;
    }
    
    /**
     * 过滤结果类 - 存储过滤后的纯文本请求和过滤统计
     */
    private static class FilterResult {
        final List<HttpRequestResponse> textMessages;
        final List<HttpRequestResponse> binaryMessages;
        
        FilterResult(List<HttpRequestResponse> textMessages, List<HttpRequestResponse> binaryMessages) {
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
    
    /**
     * 过滤二进制请求，返回纯文本请求列表和统计信息
     */
    private FilterResult filterBinaryRequests(List<HttpRequestResponse> messages) {
        List<HttpRequestResponse> textMessages = new ArrayList<>();
        List<HttpRequestResponse> binaryMessages = new ArrayList<>();
        
        for (HttpRequestResponse message : messages) {
            if (BinaryContentDetector.isTextRequest(message.request())) {
                textMessages.add(message);
            } else {
                binaryMessages.add(message);
            }
        }
        
        return new FilterResult(textMessages, binaryMessages);
    }
    
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        // 只有已连接状态才显示菜单
        if (!configManager.isConnected()) {
            return menuItems;
        }
        
        // 获取选中的请求
        List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
        if (selectedMessages == null || selectedMessages.isEmpty()) {
            // 尝试获取消息编辑器中的请求
            if (event.messageEditorRequestResponse().isPresent()) {
                HttpRequestResponse editorMessage = event.messageEditorRequestResponse().get().requestResponse();
                selectedMessages = List.of(editorMessage);
            }
        }
        
        if (selectedMessages == null || selectedMessages.isEmpty()) {
            return menuItems;
        }
        
        final List<HttpRequestResponse> messages = selectedMessages;
        
        // 过滤二进制请求
        FilterResult filterResult = filterBinaryRequests(messages);
        String menuSuffix = filterResult.getMenuSuffix();
        
        // 菜单项1: 使用默认配置发送
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
        
        // 菜单项2: 标记注入点并扫描 - 支持多选报文
        JMenuItem markInjectionPoints = new JMenuItem("标记注入点并扫描 (*)" + menuSuffix);
        if (filterResult.allBinary()) {
            markInjectionPoints.setEnabled(false);
            markInjectionPoints.setToolTipText("所有选中的报文都是二进制格式，无法发起扫描任务");
        } else {
            // 检查数量限制，超过限制时显示警告但仍然可点击
            int maxMarkCount = configManager.getMaxInjectionMarkCount();
            if (filterResult.textCount() > maxMarkCount) {
                markInjectionPoints.setToolTipText(
                    String.format("选中的纯文本报文数量(%d)超过标记上限(%d)，仅前%d个报文可进行注入点标记", 
                        filterResult.textCount(), maxMarkCount, maxMarkCount));
            }
            markInjectionPoints.addActionListener(e -> {
                if (filterResult.hasTextMessages()) {
                    // 使用新的批量注入点标记对话框
                    BatchInjectionMarkDialog dialog = new BatchInjectionMarkDialog(
                        api, apiClient, configManager, uiTab);
                    dialog.show(filterResult.textMessages, filterResult.binaryMessages);
                }
            });
        }
        menuItems.add(markInjectionPoints);
        
        // 菜单项3: 配置扫描发送（高级配置对话框）
        JMenuItem sendWithOptions = new JMenuItem("Send to SQLMap WebUI (配置扫描)..." + menuSuffix);
        if (filterResult.allBinary()) {
            sendWithOptions.setEnabled(false);
            sendWithOptions.setToolTipText("所有选中的报文都是二进制格式，无法发起扫描任务");
        } else {
            sendWithOptions.addActionListener(e -> {
                if (filterResult.hasTextMessages()) {
                    // 使用新的高级配置对话框
                    AdvancedScanConfigDialog dialog = new AdvancedScanConfigDialog(
                        api, apiClient, configManager, uiTab);
                    dialog.show(filterResult.textMessages, filterResult.binaryMessages);
                }
            });
        }
        menuItems.add(sendWithOptions);
        
        // 菜单项4和5: 提交会话Header 和 Header规则 - 仅在选中单条请求时显示
        if (messages.size() == 1 && filterResult.hasTextMessages()) {
            JMenuItem submitSessionHeaders = new JMenuItem("提交会话Header");
            submitSessionHeaders.addActionListener(e -> {
                SessionHeaderDialog dialog = new SessionHeaderDialog(api, apiClient, uiTab);
                dialog.show(filterResult.textMessages.get(0).request());
            });
            menuItems.add(submitSessionHeaders);
            
            JMenuItem submitHeaderRule = new JMenuItem("提交Header规则");
            submitHeaderRule.addActionListener(e -> {
                HeaderRuleDialog dialog = new HeaderRuleDialog(api, apiClient, uiTab);
                dialog.show(filterResult.textMessages.get(0).request());
            });
            menuItems.add(submitHeaderRule);
        }
        
        return menuItems;
    }
    
    /**
     * 发送过滤后的纯文本请求，并记录被过滤的二进制请求日志
     */
    private void sendFilteredRequests(FilterResult filterResult, ScanConfig config) {
        // 记录二进制过滤统计
        if (filterResult.binaryCount() > 0) {
            uiTab.appendLog(String.format("[*] 二进制过滤: %d 个请求已跳过",
                filterResult.binaryCount()));
            
            // 记录被过滤的二进制请求URL
            for (HttpRequestResponse binaryMsg : filterResult.binaryMessages) {
                String url = binaryMsg.request().url();
                BinaryContentDetector.DetectionResult detection = BinaryContentDetector.detect(binaryMsg.request());
                uiTab.appendLog(String.format("    [跳过-二进制] %s (原因: %s)", url, detection.getReason()));
            }
        }
        
        // 第二步：去重处理
        List<HttpRequestResponse> messagesToSend = filterResult.textMessages;
        int duplicateCount = 0;
        
        if (configManager.isAutoDedupe() && messagesToSend.size() > 1) {
            RequestDeduplicator.DedupeResult dedupeResult = RequestDeduplicator.deduplicate(messagesToSend);
            
            if (dedupeResult.hasDuplicates()) {
                duplicateCount = dedupeResult.duplicateCount();
                uiTab.appendLog(String.format("[*] 重复过滤: %d 个重复请求已跳过",
                    duplicateCount));
                
                // 记录被过滤的重复请求
                for (HttpRequestResponse dupMsg : dedupeResult.getDuplicateMessages()) {
                    String desc = RequestDeduplicator.getRequestDescription(dupMsg.request());
                    uiTab.appendLog(String.format("    [跳过-重复] %s", desc));
                }
                
                messagesToSend = dedupeResult.getUniqueMessages();
            }
        }
        
        // 输出统计汇总
        int totalSelected = filterResult.totalCount();
        int finalSendCount = messagesToSend.size();
        if (filterResult.binaryCount() > 0 || duplicateCount > 0) {
            uiTab.appendLog(String.format("[*] 最终统计: 共选中 %d 个请求，实际发送 %d 个",
                totalSelected, finalSendCount));
        }
        
        // 发送请求
        for (HttpRequestResponse message : messagesToSend) {
            sendRequestToBackend(message.request(), config);
        }
    }
    
    /**
     * 发送请求到后端 - 用于默认配置发送
     */
    private void sendRequestToBackend(HttpRequest request, ScanConfig config) {
        try {
            String url = request.url();
            String method = request.method();
            String body = request.bodyToString();
            
            // 构建headers列表
            List<String> headersList = new ArrayList<>();
            headersList.add(method + " " + request.path() + " " + request.httpVersion());
            request.headers().forEach(header -> 
                headersList.add(header.name() + ": " + header.value())
            );
            
            // 构建JSON payload
            StringBuilder headersJson = new StringBuilder("[");
            for (int i = 0; i < headersList.size(); i++) {
                headersJson.append("\"").append(JsonUtils.escapeJson(headersList.get(i))).append("\"");
                if (i < headersList.size() - 1) headersJson.append(",");
            }
            headersJson.append("]");
            
            // 构建options
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
            
            // 提取host
            String host = "";
            try {
                java.net.URL urlObj = new java.net.URL(url);
                host = urlObj.getHost();
            } catch (Exception e) {
                host = "unknown";
            }
            
            String jsonPayload = String.format(
                "{\"scanUrl\":\"%s\",\"host\":\"%s\",\"headers\":%s,\"body\":\"%s\",\"options\":%s}",
                JsonUtils.escapeJson(url),
                JsonUtils.escapeJson(host),
                headersJson.toString(),
                JsonUtils.escapeJson(body),
                optionsJson.toString()
            );
            
            // 异步发送到后端
            new Thread(() -> {
                try {
                    String response = apiClient.sendTask(jsonPayload);
                    
                    // 添加到历史记录
                    configManager.addToHistory(config);
                    
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 请求已发送: " + url);
                        uiTab.appendLog("    使用配置: " + config.getName());
                        uiTab.appendLog("    响应: " + response);
                    });
                    
                    api.logging().logToOutput("[+] Task created for: " + url);
                    
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[-] 发送请求失败: " + e.getMessage());
                    });
                    api.logging().logToError("[-] Error: " + e.getMessage());
                }
            }).start();
            
        } catch (Exception e) {
            uiTab.appendLog("[-] 处理请求失败: " + e.getMessage());
            api.logging().logToError("[-] Error: " + e.getMessage());
        }
    }
}
