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

/**
 * Context Menu Provider for SQLMap WebUI Extension (Montoya API)
 * 
 * 提供右键菜单：
 * 1. Send to SQLMap WebUI - 使用默认配置发送
 * 2. Send to SQLMap WebUI (选择配置)... - 选择配置发送
 * 3. 标记注入点并扫描 (*) - 手动标记注入点
 * 4. 提交会话Header - 提交临时会话Header
 * 5. 提交Header规则 - 提交持久化Header规则
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
        
        // 检测请求是否为二进制内容
        HttpRequest firstRequest = messages.get(0).request();
        BinaryContentDetector.DetectionResult detectionResult = BinaryContentDetector.detect(firstRequest);
        boolean isBinary = detectionResult.isBinary();
        String binarySuffix = isBinary ? " (二进制报文)" : "";
        
        // 菜单项1: 使用默认配置发送
        JMenuItem sendWithDefault = new JMenuItem("Send to SQLMap WebUI" + binarySuffix);
        if (isBinary) {
            sendWithDefault.setEnabled(false);
            sendWithDefault.setToolTipText("二进制报文无法发起扫描任务: " + detectionResult.getReason());
        } else {
            sendWithDefault.addActionListener(e -> {
                for (HttpRequestResponse message : messages) {
                    sendRequestToBackend(message.request(), configManager.getDefaultConfig());
                }
            });
        }
        menuItems.add(sendWithDefault);
        
        // 菜单项2: 选择配置发送
        JMenuItem sendWithOptions = new JMenuItem("Send to SQLMap WebUI (选择配置)..." + binarySuffix);
        if (isBinary) {
            sendWithOptions.setEnabled(false);
            sendWithOptions.setToolTipText("二进制报文无法发起扫描任务: " + detectionResult.getReason());
        } else {
            sendWithOptions.addActionListener(e -> {
                if (!messages.isEmpty()) {
                    ConfigSelectionDialog dialog = new ConfigSelectionDialog(
                        api, apiClient, configManager, uiTab);
                    dialog.show(messages.get(0).request());
                }
            });
        }
        menuItems.add(sendWithOptions);
        
        // 菜单项3: 标记注入点并扫描
        JMenuItem markInjectionPoints = new JMenuItem("标记注入点并扫描 (*)" + binarySuffix);
        if (isBinary) {
            markInjectionPoints.setEnabled(false);
            markInjectionPoints.setToolTipText("二进制报文无法发起扫描任务: " + detectionResult.getReason());
        } else {
            markInjectionPoints.addActionListener(e -> {
                if (!messages.isEmpty()) {
                    InjectionPointDialog dialog = new InjectionPointDialog(
                        api, apiClient, configManager, uiTab);
                    dialog.show(messages.get(0));
                }
            });
        }
        menuItems.add(markInjectionPoints);
        
        // 菜单项4和5: 提交会话Header 和 Header规则 - 仅在选中单条请求时显示
        if (messages.size() == 1) {
            JMenuItem submitSessionHeaders = new JMenuItem("提交会话Header");
            submitSessionHeaders.addActionListener(e -> {
                SessionHeaderDialog dialog = new SessionHeaderDialog(api, apiClient, uiTab);
                dialog.show(messages.get(0).request());
            });
            menuItems.add(submitSessionHeaders);
            
            JMenuItem submitHeaderRule = new JMenuItem("提交Header规则");
            submitHeaderRule.addActionListener(e -> {
                HeaderRuleDialog dialog = new HeaderRuleDialog(api, apiClient, uiTab);
                dialog.show(messages.get(0).request());
            });
            menuItems.add(submitHeaderRule);
        }
        
        return menuItems;
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
