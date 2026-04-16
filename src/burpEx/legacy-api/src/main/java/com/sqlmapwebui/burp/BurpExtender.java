package com.sqlmapwebui.burp;

import burp.*;

import com.sqlmapwebui.burp.dialogs.*;
import com.sqlmapwebui.burp.util.CommandExecutor;
import com.sqlmapwebui.burp.util.SqlCommandBuilder;
import com.sqlmapwebui.burp.util.TitleRule;
import com.sqlmapwebui.burp.util.TitleExtractor;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
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
    private static final String EXTENSION_VERSION = "1.8.52";
    
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
            
            // ==================== 需要后端连接的菜单项（未连接时置灰） ====================
            boolean connected = configManager.isConnected();
            
            // 使用用户选择的配置发送
            JMenuItem sendWithDefault = new JMenuItem("Send to SQLMap WebUI" + menuSuffix);
            if (!connected) {
                sendWithDefault.setEnabled(false);
                sendWithDefault.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
            } else if (filterResult.allBinary()) {
                sendWithDefault.setEnabled(false);
                sendWithDefault.setToolTipText("所有选中的报文都是二进制格式，无法发起扫描任务");
            } else {
                sendWithDefault.addActionListener(e -> {
                    // 使用用户在"右键菜单扫描使用的配置"中选择的配置
                    sendFilteredRequests(filterResult, configManager.getSelectedScanConfig());
                });
            }
            menuItems.add(sendWithDefault);
            
            // 标记注入点并扫描 - 支持多选报文
            int maxMarkCount = configManager.getMaxInjectionMarkCount();
            JMenuItem markInjectionPoints = new JMenuItem("标记注入点并扫描 (*)" + menuSuffix);
            if (!connected) {
                markInjectionPoints.setEnabled(false);
                markInjectionPoints.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
            } else if (filterResult.allBinary()) {
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
            if (!connected) {
                sendWithOptions.setEnabled(false);
                sendWithOptions.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
            } else if (filterResult.allBinary()) {
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
            
            // 提交会话Header 和 Header规则 - 仅在选中单条请求时显示，且需要后端连接
            if (selectedMessages.length == 1 && filterResult.hasTextMessages()) {
                JMenuItem submitSessionHeaders = new JMenuItem("提交会话Header");
                if (!connected) {
                    submitSessionHeaders.setEnabled(false);
                    submitSessionHeaders.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
                } else {
                    submitSessionHeaders.addActionListener(e -> {
                        SessionHeaderDialog dialog = new SessionHeaderDialog(callbacks, apiClient, uiTab);
                        dialog.show(filterResult.textMessages.get(0));
                    });
                }
                menuItems.add(submitSessionHeaders);
                
                JMenuItem submitHeaderRule = new JMenuItem("提交Header规则");
                if (!connected) {
                    submitHeaderRule.setEnabled(false);
                    submitHeaderRule.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
                } else {
                    submitHeaderRule.addActionListener(e -> {
                        HeaderRuleDialog dialog = new HeaderRuleDialog(callbacks, apiClient, uiTab);
                        dialog.show(filterResult.textMessages.get(0));
                    });
                }
                menuItems.add(submitHeaderRule);
            }
            
            // ==================== 不依赖后端的菜单项（始终可用） ====================
            
            // 复制SQLMap命令
            JMenuItem copySqlCommand = new JMenuItem("复制SQLMap命令" + menuSuffix);
            if (filterResult.allBinary()) {
                copySqlCommand.setEnabled(false);
                copySqlCommand.setToolTipText("所有选中的报文都是二进制格式，无法生成SQLMap命令");
            } else {
                copySqlCommand.addActionListener(e -> {
                    if (filterResult.hasTextMessages()) {
                        handleCopySqlCommand(filterResult.textMessages.get(0));
                    }
                });
            }
            menuItems.add(copySqlCommand);
            
            // 执行SQLMap扫描
            JMenuItem executeSqlMap = new JMenuItem("执行SQLMap扫描" + menuSuffix);
            if (filterResult.allBinary()) {
                executeSqlMap.setEnabled(false);
                executeSqlMap.setToolTipText("所有选中的报文都是二进制格式，无法执行SQLMap扫描");
            } else {
                executeSqlMap.addActionListener(e -> {
                    if (filterResult.hasTextMessages()) {
                        handleExecuteSqlMap(filterResult.textMessages.get(0));
                    }
                });
            }
            menuItems.add(executeSqlMap);
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
                body = new String(request, bodyOffset, request.length - bodyOffset, StandardCharsets.UTF_8);
            }
            
            Map<String, Object> options = config.toOptionsMap();
            
            // 提取HTTP方法（从headers的第一行）
            String method = "GET";
            if (headers != null && !headers.isEmpty()) {
                String firstHeader = headers.get(0);
                if (firstHeader != null && firstHeader.contains(" ")) {
                    method = firstHeader.substring(0, firstHeader.indexOf(" "));
                }
            }
            
            // 使用 Gson 构建 JSON，避免手动拼接导致 XML 等特殊字符转义不完备
            Gson gson = new Gson();
            JsonObject payload = new JsonObject();
            payload.addProperty("scanUrl", url);
            payload.addProperty("host", requestInfo.getUrl().getHost());
            payload.addProperty("method", method);
            payload.add("headers", gson.toJsonTree(headers));
            payload.addProperty("body", body);
            payload.add("options", gson.toJsonTree(options));
            
            String jsonPayload = gson.toJson(payload);
            
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
    
    // ==================== 新增：复制SQLMap命令和执行SQLMap扫描 ====================
    
    /**
     * 处理"复制SQLMap命令"菜单点击
     */
    private void handleCopySqlCommand(IHttpRequestResponse message) {
        try {
            // 检查SQLMap路径是否配置
            String sqlmapPath = configManager.getDirectSqlmapPath();
            if (sqlmapPath == null || sqlmapPath.trim().isEmpty()) {
                if (CommandPreviewDialog.showConfigWarning(uiTab, "SQLMap路径（请在\"直接执行配置\"选项卡中配置）")) {
                    uiTab.switchToDirectExecuteTab();
                }
                return;
            }

            // 生成HTTP请求字符串
            String httpRequest = buildHttpRequest(message);
            
            // 生成临时文件
            String requestFilePath = SqlCommandBuilder.generateRequestFile(
                httpRequest, 
                configManager.getClipboardTempDir()
            );
            
            // 构建SQLMap命令
            String command = SqlCommandBuilder.buildCopyableCommand(
                configManager.getDirectPythonPath(),
                sqlmapPath,
                requestFilePath,
                buildAdditionalParams(configManager.getSelectedScanConfig())
            );
            
            // 根据配置决定是直接复制还是显示预览
            if (configManager.isClipboardAutoCopy()) {
                // 直接复制到剪贴板
                CommandExecutor.copyToClipboard(command);
                uiTab.appendLog("[+] SQLMap命令已复制到剪贴板");
                uiTab.appendLog("    请求文件: " + requestFilePath);
                JOptionPane.showMessageDialog(uiTab, 
                    "SQLMap命令已复制到剪贴板!\n\n" +
                    "请求文件: " + requestFilePath,
                    "复制成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                // 显示预览对话框
                CommandPreviewDialog dialog = new CommandPreviewDialog(configManager);
                dialog.showCopyDialog(uiTab, command, requestFilePath);
            }
            
        } catch (Exception e) {
            uiTab.appendLog("[-] 生成SQLMap命令失败: " + e.getMessage());
            JOptionPane.showMessageDialog(uiTab, 
                "生成SQLMap命令失败:\n" + e.getMessage(),
                "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 处理"执行SQLMap扫描"菜单点击
     */
    private void handleExecuteSqlMap(IHttpRequestResponse message) {
        try {
            // 检查SQLMap路径是否配置
            String sqlmapPath = configManager.getDirectSqlmapPath();
            if (sqlmapPath == null || sqlmapPath.isEmpty()) {
                if (CommandPreviewDialog.showConfigWarning(uiTab, "SQLMap路径")) {
                    uiTab.switchToDirectExecuteTab();
                }
                return;
            }
            
            // 提取窗口标题（使用多规则匹配）
            List<TitleRule> rules = configManager.getTitleRules();
            String fallback = configManager.getTitleFallback();
            int maxLength = configManager.getTitleMaxLength();

            // 调试日志：打印规则列表
            uiTab.appendLog("[DEBUG] 标题规则数量: " + rules.size());
            for (TitleRule r : rules) {
                uiTab.appendLog("[DEBUG]   - 规则: " + r.getName() + ", 类型: " + r.getSourceType() +
                    ", 启用: " + r.isEnabled() + ", 优先级: " + r.getPriority());
            }
            uiTab.appendLog("[DEBUG] Fallback: " + fallback + ", MaxLength: " + maxLength);

            String windowTitle = TitleExtractor.extract(message, helpers, rules, fallback, maxLength);
            uiTab.appendLog("[DEBUG] 提取到的标题: " + windowTitle);
            
            // 生成HTTP请求字符串
            String httpRequest = buildHttpRequest(message);
            
            // 生成临时文件
            String requestFilePath = SqlCommandBuilder.generateRequestFile(
                httpRequest, 
                configManager.getClipboardTempDir()
            );
            
            // 构建SQLMap命令
            String sqlmapCommand = SqlCommandBuilder.buildSqlMapCommand(
                configManager.getDirectPythonPath(),
                configManager.getDirectSqlmapPath(),
                requestFilePath,
                buildAdditionalParams(configManager.getSelectedScanConfig())
            );
            
            // 构建终端命令（带标题）
            String terminalCommand = SqlCommandBuilder.buildTerminalCommand(
                sqlmapCommand,
                configManager.getDirectTerminalType(),
                configManager.isDirectKeepTerminal(),
                windowTitle
            );
            
            uiTab.appendLog("[+] 正在启动SQLMap扫描...");
            uiTab.appendLog("    窗口标题: " + windowTitle);
            uiTab.appendLog("    请求文件: " + requestFilePath);
            uiTab.appendLog("    脚本目录: " + (configManager.getScriptTempDir().isEmpty() ? "(使用临时目录)" : configManager.getScriptTempDir()));
            
            // 执行命令
            CommandExecutor.ExecutionResult result = CommandExecutor.executeInTerminal(
                sqlmapCommand,
                configManager.getDirectTerminalType(),
                configManager.isDirectKeepTerminal(),
                windowTitle,
                configManager.getScriptTempDir()
            );
            
            if (result.isSuccess()) {
                uiTab.appendLog("[+] SQLMap扫描已在终端中启动");
                uiTab.appendLog("    " + result.getMessage());
                JOptionPane.showMessageDialog(uiTab, 
                    "SQLMap扫描已在终端中启动!\n\n" +
                    result.getMessage() + "\n\n" +
                    "终端窗口会独立运行，您可以继续使用Burp。",
                    "执行成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                uiTab.appendLog("[-] 启动终端失败: " + result.getMessage());
                JOptionPane.showMessageDialog(uiTab, 
                    "启动终端失败:\n" + result.getMessage(),
                    "执行失败", JOptionPane.ERROR_MESSAGE);
            }
            
        } catch (Exception e) {
            uiTab.appendLog("[-] 执行SQLMap扫描失败: " + e.getMessage());
            JOptionPane.showMessageDialog(uiTab, 
                "执行SQLMap扫描失败:\n" + e.getMessage(),
                "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 从IHttpRequestResponse构建HTTP请求字符串
     */
    /**
     * 构建HTTP请求内容字符串
     * 
     * 防御性修复：去除尾部多余空行，避免SQLMap -r模式误将GET识别为POST
     * (SQLMap在请求文件末尾存在多余空行时会错误推断存在body并切换为POST方法)
     */
    private String buildHttpRequest(IHttpRequestResponse message) {
        StringBuilder request = new StringBuilder();
        
        // 获取请求信息
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        
        // 请求行
        String method = requestInfo.getMethod();
        String path = requestInfo.getUrl().getPath();
        String query = requestInfo.getUrl().getQuery();
        
        request.append(method).append(" ").append(path);
        if (query != null && !query.isEmpty()) {
            request.append("?").append(query);
        }
        request.append(" HTTP/1.1\r\n");
        
        // 请求头
        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            request.append(header).append("\r\n");
        }
        
        // 空行
        request.append("\r\n");
        
        // 请求体
        byte[] body = message.getRequest();
        if (body != null && body.length > 0) {
            int bodyOffset = requestInfo.getBodyOffset();
            String bodyStr = new String(body, bodyOffset, body.length - bodyOffset, StandardCharsets.UTF_8);
            request.append(bodyStr);
        }
        
        // 去除尾部多余换行符，确保SQLMap -r模式正确识别请求方法
        String result = request.toString();
        while (result.endsWith("\r\n\r\n")) {
            result = result.substring(0, result.length() - 2);
        }
        while (result.endsWith("\n\n")) {
            result = result.substring(0, result.length() - 1);
        }
        
        return result;
    }
    
    /**
     * 构建额外的SQLMap参数（CLI格式）
     */
    private String buildAdditionalParams(ScanConfig config) {
        if (config == null) {
            return "";
        }
        // 使用 toCommandLineString() 生成正确的 CLI 参数（如 --random-agent, --batch 等）
        return config.toCommandLineString().trim();
    }
}

