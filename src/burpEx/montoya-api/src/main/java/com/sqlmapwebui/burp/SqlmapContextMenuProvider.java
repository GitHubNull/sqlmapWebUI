package com.sqlmapwebui.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.sqlmapwebui.burp.dialogs.*;
import com.sqlmapwebui.burp.util.CommandExecutor;
import com.sqlmapwebui.burp.util.PayloadBuilder;
import com.sqlmapwebui.burp.util.SqlCommandBuilder;
import com.sqlmapwebui.burp.util.TitleConfig;
import com.sqlmapwebui.burp.util.TitleExtractor;

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

        // ==================== 需要后端连接的菜单项（未连接时置灰） ====================
        boolean connected = configManager.isConnected();
        
        // 菜单项1: 使用用户选择的配置发送
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
        
        // 菜单项2: 标记注入点并扫描 - 支持多选报文
        JMenuItem markInjectionPoints = new JMenuItem("标记注入点并扫描 (*)" + menuSuffix);
        if (!connected) {
            markInjectionPoints.setEnabled(false);
            markInjectionPoints.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
        } else if (filterResult.allBinary()) {
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
                        api, apiClient, configManager, uiTab);
                    dialog.show(filterResult.textMessages, filterResult.binaryMessages);
                }
            });
        }
        menuItems.add(sendWithOptions);
        
        // 菜单项4和5: 提交会话Header 和 Header规则 - 仅在选中单条请求时显示，且需要后端连接
        if (messages.size() == 1 && filterResult.hasTextMessages()) {
            JMenuItem submitSessionHeaders = new JMenuItem("提交会话Header");
            if (!connected) {
                submitSessionHeaders.setEnabled(false);
                submitSessionHeaders.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
            } else {
                submitSessionHeaders.addActionListener(e -> {
                    SessionHeaderDialog dialog = new SessionHeaderDialog(api, apiClient, uiTab);
                    dialog.show(filterResult.textMessages.get(0).request());
                });
            }
            menuItems.add(submitSessionHeaders);
            
            JMenuItem submitHeaderRule = new JMenuItem("提交Header规则");
            if (!connected) {
                submitHeaderRule.setEnabled(false);
                submitHeaderRule.setToolTipText("未连接到SQLMap WebUI后端，请检查连接配置");
            } else {
                submitHeaderRule.addActionListener(e -> {
                    HeaderRuleDialog dialog = new HeaderRuleDialog(api, apiClient, uiTab);
                    dialog.show(filterResult.textMessages.get(0).request());
                });
            }
            menuItems.add(submitHeaderRule);
        }
        
        // ==================== 不依赖后端的菜单项（始终可用） ====================
        // 添加分隔线
        menuItems.add(new JSeparator());
        
        // 菜单项6: 复制SQLMap命令 - 使用 -r 参数生成命令
        JMenuItem copySqlCommand = new JMenuItem("复制SQLMap命令" + menuSuffix);
        if (filterResult.allBinary()) {
            copySqlCommand.setEnabled(false);
            copySqlCommand.setToolTipText("所有选中的报文都是二进制格式，无法生成SQLMap命令");
        } else {
            copySqlCommand.addActionListener(e -> {
                handleCopySqlCommand(filterResult.textMessages);
            });
        }
        menuItems.add(copySqlCommand);
        
        // 菜单项7: 执行SQLMap扫描 - 在终端中执行
        JMenuItem executeSqlmap = new JMenuItem("执行SQLMap扫描" + menuSuffix);
        if (filterResult.allBinary()) {
            executeSqlmap.setEnabled(false);
            executeSqlmap.setToolTipText("所有选中的报文都是二进制格式，无法执行SQLMap扫描");
        } else {
            // 检查配置是否完整
            String sqlmapPath = configManager.getDirectSqlmapPath();
            if (sqlmapPath == null || sqlmapPath.trim().isEmpty()) {
                executeSqlmap.setEnabled(false);
                executeSqlmap.setToolTipText("请先配置SQLMap路径（在\"直接执行配置\"选项卡中设置）");
            } else {
                executeSqlmap.addActionListener(e -> {
                    handleExecuteSqlmap(filterResult.textMessages);
                });
            }
        }
        menuItems.add(executeSqlmap);
        
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
            // 使用UTF-8编码获取body，避免中文乱码
            String body = HttpRequestUtils.getBodyAsUtf8(request);
            
            // 构建headers列表
            List<String> headersList = new ArrayList<>();
            headersList.add(method + " " + request.path() + " " + request.httpVersion());
            request.headers().forEach(header -> 
                headersList.add(header.name() + ": " + header.value())
            );
            
            // 提取host
            String host = "";
            try {
                java.net.URL urlObj = new java.net.URL(url);
                host = urlObj.getHost();
            } catch (Exception e) {
                host = "unknown";
            }
            
            // 构建options
            Map<String, Object> options = config.toOptionsMap();
            
             // 使用 PayloadBuilder 构建JSON
            String jsonPayload = PayloadBuilder.buildTaskPayload(
                url,
                host,
                request.method(),
                headersList,
                body,
                options
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
                        uiTab.refreshHistoryTable();
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
    
    /**
     * 处理复制SQLMap命令
     * 生成HTTP请求临时文件并构建SQLMap命令
     */
    private void handleCopySqlCommand(List<HttpRequestResponse> messages) {
        if (messages.isEmpty()) {
            return;
        }

        // 检查SQLMap路径是否配置（在UI线程中执行弹框）
        String sqlmapPath = configManager.getDirectSqlmapPath();
        if (sqlmapPath == null || sqlmapPath.trim().isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                if (CommandPreviewDialog.showConfigWarning(null, "SQLMap路径（请在\"直接执行配置\"选项卡中配置）")) {
                    uiTab.appendLog("[*] 请在\"直接执行配置\"选项卡中配置SQLMap路径");
                }
            });
            return;
        }

        new Thread(() -> {
            try {
                String pythonPath = configManager.getDirectPythonPath();
                String tempDir = configManager.getClipboardTempDir();
                boolean autoCopy = configManager.isClipboardAutoCopy();

                // 获取扫描配置参数
                ScanConfig scanConfig = configManager.getSelectedScanConfig();
                String additionalParams = (scanConfig != null) ? scanConfig.toCommandLineString().trim() : "";

                // 为每个请求生成命令
                StringBuilder allCommands = new StringBuilder();
                java.util.List<String> tempFiles = new ArrayList<>();

                for (HttpRequestResponse message : messages) {
                    HttpRequest request = message.request();
                    
                    // 构建HTTP请求内容
                    String httpRequest = buildHttpRequestContent(request);
                    
                    // 生成临时文件
                    String tempFilePath = SqlCommandBuilder.generateRequestFile(httpRequest, tempDir);
                    tempFiles.add(tempFilePath);
                    
                    // 构建SQLMap命令（含扫描参数）
                    String command = SqlCommandBuilder.buildCopyableCommand(pythonPath, sqlmapPath, tempFilePath, additionalParams);
                    
                    allCommands.append(command).append("\n\n");
                    
                    final String url = request.url();
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 已生成SQLMap命令: " + url);
                        uiTab.appendLog("    临时文件: " + tempFilePath);
                    });
                }

                String finalCommands = allCommands.toString().trim();

                // 根据配置决定是否自动复制
                if (autoCopy) {
                    CommandExecutor.copyToClipboard(finalCommands);
                    SwingUtilities.invokeLater(() -> {
                        CommandPreviewDialog.showCopySuccess(null);
                        uiTab.appendLog("[+] SQLMap命令已复制到剪贴板");
                    });
                } else {
                    // 显示预览对话框
                    String firstTempFile = tempFiles.isEmpty() ? null : tempFiles.get(0);
                    SwingUtilities.invokeLater(() -> {
                        CommandPreviewDialog.quickShowCopy(null, finalCommands, firstTempFile);
                    });
                }

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    uiTab.appendLog("[-] 生成SQLMap命令失败: " + e.getMessage());
                    CommandPreviewDialog.showError(null, "错误", "生成命令失败: " + e.getMessage());
                });
            }
        }).start();
    }
    
    /**
     * 处理执行SQLMap扫描
     * 生成HTTP请求临时文件并在终端中执行SQLMap
     */
    private void handleExecuteSqlmap(List<HttpRequestResponse> messages) {
        if (messages.isEmpty()) {
            return;
        }

        // 检查配置
        String sqlmapPath = configManager.getDirectSqlmapPath();
        if (sqlmapPath == null || sqlmapPath.trim().isEmpty()) {
            if (CommandPreviewDialog.showConfigWarning(null, "SQLMap路径")) {
                // 用户想配置，这里可以打开配置面板（需要扩展实现）
                uiTab.appendLog("[*] 请在\"直接执行配置\"选项卡中配置SQLMap路径");
            }
            return;
        }

        new Thread(() -> {
            try {
                String pythonPath = configManager.getDirectPythonPath();
                ConfigManager.TerminalType terminalType = configManager.getDirectTerminalType();
                boolean keepTerminal = configManager.isDirectKeepTerminal();
                String tempDir = configManager.getClipboardTempDir();
                
                // 获取标题配置
                TitleConfig titleConfig = configManager.getTitleConfig();

                // 为每个请求执行SQLMap
                int index = 0;
                for (HttpRequestResponse message : messages) {
                    index++;
                    HttpRequest request = message.request();
                    
                    // 构建HTTP请求内容
                    String httpRequest = buildHttpRequestContent(request);
                    
                    // 生成临时文件
                    String tempFilePath = SqlCommandBuilder.generateRequestFile(httpRequest, tempDir);
                    
                    // 获取扫描配置参数
                    ScanConfig scanConfig = configManager.getSelectedScanConfig();
                    String additionalParams = (scanConfig != null) ? scanConfig.toCommandLineString().trim() : "";
                    
                    // 构建SQLMap命令
                    String sqlmapCommand = SqlCommandBuilder.buildSqlMapCommand(
                        pythonPath, sqlmapPath, tempFilePath, additionalParams);
                    
                    // 提取窗口标题
                    String baseTitle = TitleExtractor.extract(request, titleConfig);
                    
                    // 批量执行时添加序号后缀
                    String windowTitle;
                    if (messages.size() > 1) {
                        windowTitle = baseTitle + "-" + index;
                    } else {
                        windowTitle = baseTitle;
                    }
                    
                    // 构建完整的终端命令（带标题）
                    String terminalCommand = SqlCommandBuilder.buildTerminalCommand(
                        sqlmapCommand, terminalType, keepTerminal, windowTitle);
                    
                    final String url = request.url();
                    final String finalWindowTitle = windowTitle;
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 执行SQLMap扫描: " + url);
                        uiTab.appendLog("    窗口标题: " + finalWindowTitle);
                        uiTab.appendLog("    临时文件: " + tempFilePath);
                    });

                    // 执行命令
                    CommandExecutor.ExecutionResult result = CommandExecutor.executeInTerminal(
                        sqlmapCommand, terminalType, keepTerminal);
                    
                    if (!result.isSuccess()) {
                        SwingUtilities.invokeLater(() -> {
                            uiTab.appendLog("[-] 启动SQLMap失败: " + result.getMessage());
                        });
                    }
                    
                    // 每个请求之间稍微延迟
                    Thread.sleep(500);
                }

                SwingUtilities.invokeLater(() -> {
                    uiTab.appendLog("[+] 所有SQLMap命令已启动 (" + messages.size() + " 个)");
                });

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    uiTab.appendLog("[-] 执行SQLMap失败: " + e.getMessage());
                    CommandPreviewDialog.showError(null, "错误", "执行失败: " + e.getMessage());
                });
            }
        }).start();
    }
    
    /**
     * 构建HTTP请求内容字符串
     */
    private String buildHttpRequestContent(HttpRequest request) {
        StringBuilder sb = new StringBuilder();
        
        // 请求行
        sb.append(request.method()).append(" ")
          .append(request.path()).append(" ")
          .append(request.httpVersion()).append("\r\n");
        
        // 请求头
        request.headers().forEach(header -> {
            sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
        });
        
        // 空行
        sb.append("\r\n");
        
        // 请求体
        String body = HttpRequestUtils.getBodyAsUtf8(request);
        if (body != null && !body.isEmpty()) {
            sb.append(body);
        }
        
        return sb.toString();
    }
}
