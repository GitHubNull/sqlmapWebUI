package com.sqlmapwebui.burp;

import burp.*;

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
        stdout.println("[+] 右键菜单: Send to SQLMap WebUI / Send to SQLMap WebUI (选择配置)...");
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
        // 确保UI已初始化
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
            
            // 检测请求是否为二进制内容
            IHttpRequestResponse firstMessage = selectedMessages[0];
            BinaryContentDetector.DetectionResult detectionResult = 
                BinaryContentDetector.detect(firstMessage, helpers);
            boolean isBinary = detectionResult.isBinary();
            String binarySuffix = isBinary ? " (二进制报文)" : "";
            
            // 使用默认配置发送
            JMenuItem sendWithDefault = new JMenuItem("Send to SQLMap WebUI" + binarySuffix);
            if (isBinary) {
                sendWithDefault.setEnabled(false);
                sendWithDefault.setToolTipText("二进制报文无法发起扫描任务: " + detectionResult.getReason());
            } else {
                sendWithDefault.addActionListener(e -> {
                    for (IHttpRequestResponse message : selectedMessages) {
                        sendRequestToBackend(message, configManager.getDefaultConfig());
                    }
                });
            }
            menuItems.add(sendWithDefault);
            
            // 选择配置发送
            JMenuItem sendWithOptions = new JMenuItem("Send to SQLMap WebUI (选择配置)..." + binarySuffix);
            if (isBinary) {
                sendWithOptions.setEnabled(false);
                sendWithOptions.setToolTipText("二进制报文无法发起扫描任务: " + detectionResult.getReason());
            } else {
                sendWithOptions.addActionListener(e -> {
                    showConfigSelectionDialog(selectedMessages[0]);
                });
            }
            menuItems.add(sendWithOptions);
            
            // 标记注入点并扫描 - 新功能
            JMenuItem markInjectionPoints = new JMenuItem("标记注入点并扫描 (*)" + binarySuffix);
            if (isBinary) {
                markInjectionPoints.setEnabled(false);
                markInjectionPoints.setToolTipText("二进制报文无法发起扫描任务: " + detectionResult.getReason());
            } else {
                markInjectionPoints.addActionListener(e -> {
                    showMarkInjectionPointsDialog(selectedMessages[0]);
                });
            }
            menuItems.add(markInjectionPoints);
            
            // 提交会话Header - 仅在选中单条请求时显示
            if (selectedMessages.length == 1) {
                JMenuItem submitSessionHeaders = new JMenuItem("提交会话Header");
                submitSessionHeaders.addActionListener(e -> {
                    showSessionHeaderDialog(selectedMessages[0]);
                });
                menuItems.add(submitSessionHeaders);
                
                // 提交Header规则 - 仅在选中单条请求时显示
                JMenuItem submitHeaderRule = new JMenuItem("提交Header规则");
                submitHeaderRule.addActionListener(e -> {
                    showHeaderRuleDialog(selectedMessages[0]);
                });
                menuItems.add(submitHeaderRule);
            }
        }
        
        return menuItems;
    }
    
    /**
     * 显示标记注入点对话框
     */
    private void showMarkInjectionPointsDialog(IHttpRequestResponse requestResponse) {
        JDialog dialog = new JDialog((Frame) null, "标记SQL注入点", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(800, 700);
        dialog.setLocationRelativeTo(null);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 说明标签 - 使用JEditorPane确保HTML正确渲染
        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder("使用说明"));
        JEditorPane helpPane = new JEditorPane();
        helpPane.setContentType("text/html");
        helpPane.setEditable(false);
        helpPane.setOpaque(false);
        helpPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        helpPane.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        helpPane.setText(
            "<html><body style='font-family:sans-serif;'>" +
            "<b>在请求中使用 <span style='color:red;'>*</span> 标记注入点</b><br>" +
            "示例: id=1<span style='color:red;'>*</span>&amp;name=test → 只测试id参数<br>" +
            "示例: Cookie: session=abc<span style='color:red;'>*</span> → 测试Cookie值<br>" +
            "示例: {\"user\":\"admin<span style='color:red;'>*</span>\"} → 测试JSON字段<br>" +
            "<span style='color:gray;'>提示: 可标记多个注入点，sqlmap会依次测试</span>" +
            "</body></html>"
        );
        helpPanel.add(helpPane, BorderLayout.CENTER);
        contentPanel.add(helpPanel, BorderLayout.NORTH);
        
        // HTTP请求编辑区
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("HTTP请求 (可编辑)"));
        
        byte[] requestBytes = requestResponse.getRequest();
        String requestText = new String(requestBytes);
        
        JTextArea requestArea = new JTextArea(requestText);
        requestArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        requestArea.setLineWrap(false);
        requestArea.setWrapStyleWord(false);
        
        JScrollPane scrollPane = new JScrollPane(requestArea);
        scrollPane.setRowHeaderView(new TextLineNumber(requestArea));
        requestPanel.add(scrollPane, BorderLayout.CENTER);
        
        // 工具按钮栏
        JPanel toolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton insertMarkBtn = new JButton("插入标记 (*)");
        insertMarkBtn.addActionListener(e -> {
            int pos = requestArea.getCaretPosition();
            requestArea.insert("*", pos);
            requestArea.requestFocus();
        });
        toolPanel.add(insertMarkBtn);
        
        JButton clearMarksBtn = new JButton("清除所有标记");
        clearMarksBtn.addActionListener(e -> {
            String text = requestArea.getText();
            requestArea.setText(text.replace("*", ""));
        });
        toolPanel.add(clearMarksBtn);
        
        JLabel markCountLabel = new JLabel("标记数: 0");
        toolPanel.add(Box.createHorizontalStrut(20));
        toolPanel.add(markCountLabel);
        
        requestArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void updateCount() {
                String text = requestArea.getText();
                long count = text.chars().filter(ch -> ch == '*').count();
                markCountLabel.setText("标记数: " + count);
                markCountLabel.setForeground(count > 0 ? new Color(0, 150, 0) : Color.GRAY);
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateCount(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateCount(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateCount(); }
        });
        
        requestPanel.add(toolPanel, BorderLayout.SOUTH);
        contentPanel.add(requestPanel, BorderLayout.CENTER);
        
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        // 底部按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton scanButton = new JButton("发送扫描");
        scanButton.addActionListener(e -> {
            String markedRequest = requestArea.getText();
            
            if (!markedRequest.contains("*")) {
                int confirm = JOptionPane.showConfirmDialog(dialog,
                    "未检测到注入点标记 (*)，确定要继续吗？\nsqlmap将自动检测所有参数。",
                    "确认", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (confirm != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            
            sendMarkedRequestToBackend(requestResponse, markedRequest);
            dialog.dispose();
        });
        buttonPanel.add(scanButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(cancelButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }
    
    /**
     * 发送带标记的请求到后端
     */
    private void sendMarkedRequestToBackend(IHttpRequestResponse originalRequest, String markedRequestText) {
        try {
            byte[] markedRequestBytes = markedRequestText.getBytes();
            IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest.getHttpService(), markedRequestBytes);
            
            String url = requestInfo.getUrl().toString();
            List<String> headers = requestInfo.getHeaders();
            
            int bodyOffset = requestInfo.getBodyOffset();
            String body = "";
            if (bodyOffset < markedRequestBytes.length) {
                body = new String(markedRequestBytes, bodyOffset, markedRequestBytes.length - bodyOffset);
            }
            
            ScanConfig config = configManager.getDefaultConfig().copy();
            
            StringBuilder headersJson = new StringBuilder("[");
            for (int i = 0; i < headers.size(); i++) {
                headersJson.append("\"").append(escapeJson(headers.get(i))).append("\"");
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
                    optionsJson.append("\"").append(escapeJson((String)entry.getValue())).append("\"");
                } else if (entry.getValue() instanceof Boolean) {
                    optionsJson.append(entry.getValue());
                } else {
                    optionsJson.append(entry.getValue());
                }
            }
            optionsJson.append("}");
            
            String jsonPayload = String.format(
                "{\"scanUrl\":\"%s\",\"host\":\"%s\",\"headers\":%s,\"body\":\"%s\",\"options\":%s}",
                escapeJson(url),
                escapeJson(requestInfo.getUrl().getHost()),
                headersJson.toString(),
                escapeJson(body),
                optionsJson.toString()
            );
            
            long markCount = markedRequestText.chars().filter(ch -> ch == '*').count();
            
            new Thread(() -> {
                try {
                    String response = apiClient.sendTask(jsonPayload);
                    
                    final long finalMarkCount = markCount;
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 已发送带标记的请求: " + url);
                        uiTab.appendLog("    注入点标记数: " + finalMarkCount);
                        uiTab.appendLog("    响应: " + response);
                    });
                    
                    stdout.println("[+] Task created with " + markCount + " injection point(s) for: " + url);
                    
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
    
    /**
     * 简单的行号显示组件
     */
    private static class TextLineNumber extends JPanel {
        private final JTextArea textArea;
        private final Font font;
        
        public TextLineNumber(JTextArea textArea) {
            this.textArea = textArea;
            this.font = new Font("Monospaced", Font.PLAIN, 12);
            setPreferredSize(new Dimension(45, Integer.MAX_VALUE));
            setBackground(new Color(240, 240, 240));
            
            textArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                public void insertUpdate(javax.swing.event.DocumentEvent e) { repaint(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { repaint(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { repaint(); }
            });
        }
        
        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            g.setFont(font);
            g.setColor(Color.GRAY);
            
            FontMetrics fm = g.getFontMetrics();
            int lineHeight = fm.getHeight();
            int ascent = fm.getAscent();
            
            int lines = textArea.getLineCount();
            for (int i = 0; i < lines; i++) {
                String lineNum = String.valueOf(i + 1);
                int y = (i + 1) * lineHeight - (lineHeight - ascent);
                g.drawString(lineNum, 5, y);
            }
        }
    }
    
    /**
     * 显示配置选择对话框
     */
    private void showConfigSelectionDialog(IHttpRequestResponse requestResponse) {
        JDialog dialog = new JDialog((Frame) null, "选择扫描配置", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(500, 400);
        dialog.setLocationRelativeTo(null);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        DefaultListModel<ConfigManager.ConfigOption> listModel = new DefaultListModel<>();
        for (ConfigManager.ConfigOption option : configManager.getAllConfigOptions()) {
            listModel.addElement(option);
        }
        
        JList<ConfigManager.ConfigOption> configList = new JList<>(listModel);
        configList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        configList.setCellRenderer(new ConfigOptionRenderer());
        configList.setSelectedIndex(0);
        
        JScrollPane listScrollPane = new JScrollPane(configList);
        listScrollPane.setBorder(BorderFactory.createTitledBorder("选择配置"));
        contentPanel.add(listScrollPane, BorderLayout.CENTER);
        
        JTextArea previewArea = new JTextArea(6, 40);
        previewArea.setEditable(false);
        previewArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane previewScrollPane = new JScrollPane(previewArea);
        previewScrollPane.setBorder(BorderFactory.createTitledBorder("配置预览"));
        contentPanel.add(previewScrollPane, BorderLayout.SOUTH);
        
        configList.addListSelectionListener(e -> {
            ConfigManager.ConfigOption selected = configList.getSelectedValue();
            if (selected != null && !selected.isSeparator() && selected.getConfig() != null) {
                ScanConfig config = selected.getConfig();
                previewArea.setText(String.format(
                    "名称: %s\n描述: %s\nLevel: %d, Risk: %d\nDBMS: %s\nTechnique: %s\nBatch: %s",
                    config.getName(),
                    config.getDescription() != null ? config.getDescription() : "-",
                    config.getLevel(), config.getRisk(),
                    config.getDbms().isEmpty() ? "自动检测" : config.getDbms(),
                    config.getTechnique().isEmpty() ? "全部" : config.getTechnique(),
                    config.isBatch() ? "是" : "否"
                ));
            }
        });
        configList.setSelectedIndex(0);
        
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton sendButton = new JButton("发送扫描");
        sendButton.addActionListener(e -> {
            ConfigManager.ConfigOption selected = configList.getSelectedValue();
            if (selected != null && !selected.isSeparator() && selected.getConfig() != null) {
                sendRequestToBackend(requestResponse, selected.getConfig());
                dialog.dispose();
            } else {
                JOptionPane.showMessageDialog(dialog, "请选择一个有效的配置", 
                    "提示", JOptionPane.WARNING_MESSAGE);
            }
        });
        buttonPanel.add(sendButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(cancelButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }
    
    /**
     * 配置选项渲染器
     */
    private static class ConfigOptionRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, 
                int index, boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof ConfigManager.ConfigOption) {
                ConfigManager.ConfigOption option = (ConfigManager.ConfigOption) value;
                if (option.isSeparator()) {
                    setEnabled(false);
                    setBackground(new Color(240, 240, 240));
                    setForeground(Color.GRAY);
                } else {
                    setEnabled(true);
                }
            }
            return this;
        }
    }
    
    /**
     * 发送请求到后端
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
                headersJson.append("\"").append(escapeJson(headers.get(i))).append("\"");
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
                    optionsJson.append("\"").append(escapeJson((String)entry.getValue())).append("\"");
                } else if (entry.getValue() instanceof Boolean) {
                    optionsJson.append(entry.getValue());
                } else {
                    optionsJson.append(entry.getValue());
                }
            }
            optionsJson.append("}");
            
            String jsonPayload = String.format(
                "{\"scanUrl\":\"%s\",\"host\":\"%s\",\"headers\":%s,\"body\":\"%s\",\"options\":%s}",
                escapeJson(url),
                escapeJson(requestInfo.getUrl().getHost()),
                headersJson.toString(),
                escapeJson(body),
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
    
    /**
     * Escape special characters for JSON
     */
    private String escapeJson(String text) {
        if (text == null) return "";
        return text
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
    
    // 常见的会话相关Header名称（不区分大小写匹配）
    private static final java.util.Set<String> COMMON_SESSION_HEADERS = new java.util.HashSet<>(java.util.Arrays.asList(
        "cookie", "authorization", "x-auth-token", "x-access-token", "x-api-key",
        "x-csrf-token", "x-xsrf-token", "session-token", "bearer", "token",
        "x-session-id", "x-session-token", "x-user-token", "x-request-id",
        "x-correlation-id", "x-trace-id"
    ));
    
    /**
     * 显示会话Header配置对话框
     */
    private void showSessionHeaderDialog(IHttpRequestResponse requestResponse) {
        JDialog dialog = new JDialog((Frame) null, "提交会话Header", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(900, 700);
        dialog.setLocationRelativeTo(null);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 说明面板
        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder("使用说明"));
        JEditorPane helpPane = new JEditorPane();
        helpPane.setContentType("text/html");
        helpPane.setEditable(false);
        helpPane.setOpaque(false);
        helpPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        helpPane.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        helpPane.setText(
            "<html><body style='font-family:sans-serif;'>" +
            "<b>选择要提交的会话相关Header字段</b><br>" +
            "常见会话Header（如Cookie、Authorization等）已默认勾选<br>" +
            "<span style='color:gray;'>提示: 会话Header将临时存储，用于后续的扫描任务</span>" +
            "</body></html>"
        );
        helpPanel.add(helpPane, BorderLayout.CENTER);
        contentPanel.add(helpPanel, BorderLayout.NORTH);
        
        // 中间部分: Header选择列表
        JPanel headerSelectionPanel = new JPanel(new BorderLayout(5, 5));
        headerSelectionPanel.setBorder(BorderFactory.createTitledBorder("请求Header列表"));
        
        // 提取请求头
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
        List<String> rawHeaders = requestInfo.getHeaders();
        java.util.List<String[]> headerItems = new java.util.ArrayList<>();
        // 跳过第一行（请求行）
        for (int i = 1; i < rawHeaders.size(); i++) {
            String line = rawHeaders.get(i);
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                String value = line.substring(colonIdx + 1).trim();
                headerItems.add(new String[]{name, value});
            }
        }
        
        // 创建表格模型
        String[] columnNames = {"选择", "Header名称", "Header值"};
        Object[][] tableData = new Object[headerItems.size()][3];
        for (int i = 0; i < headerItems.size(); i++) {
            String headerName = headerItems.get(i)[0];
            String headerValue = headerItems.get(i)[1];
            // 判断是否为常见会话Header，默认勾选
            boolean isSessionHeader = COMMON_SESSION_HEADERS.contains(headerName.toLowerCase());
            tableData[i] = new Object[]{isSessionHeader, headerName, headerValue};
        }
        
        javax.swing.table.DefaultTableModel tableModel = new javax.swing.table.DefaultTableModel(tableData, columnNames) {
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // 只有复选框可编辑
            }
        };
        
        JTable headerTable = new JTable(tableModel);
        headerTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        headerTable.getColumnModel().getColumn(0).setMaxWidth(60);
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        headerTable.getColumnModel().getColumn(2).setPreferredWidth(400);
        headerTable.setRowHeight(24);
        
        JScrollPane tableScrollPane = new JScrollPane(headerTable);
        headerSelectionPanel.add(tableScrollPane, BorderLayout.CENTER);
        
        // 全选/取消全选按钮
        JPanel tableButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selectAllBtn = new JButton("全选");
        selectAllBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(true, i, 0);
            }
        });
        JButton deselectAllBtn = new JButton("取消全选");
        deselectAllBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(false, i, 0);
            }
        });
        JButton selectSessionBtn = new JButton("只选会话Header");
        selectSessionBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                String name = (String) tableModel.getValueAt(i, 1);
                boolean isSession = COMMON_SESSION_HEADERS.contains(name.toLowerCase());
                tableModel.setValueAt(isSession, i, 0);
            }
        });
        tableButtonPanel.add(selectAllBtn);
        tableButtonPanel.add(deselectAllBtn);
        tableButtonPanel.add(selectSessionBtn);
        headerSelectionPanel.add(tableButtonPanel, BorderLayout.SOUTH);
        
        contentPanel.add(headerSelectionPanel, BorderLayout.CENTER);
        
        // 作用域配置面板
        JPanel scopePanel = new JPanel(new GridBagLayout());
        scopePanel.setBorder(BorderFactory.createTitledBorder("作用域配置（可选）"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // 从请求中提取主机名
        String hostFromRequest = requestInfo.getUrl().getHost();
        
        JCheckBox enableScopeCheck = new JCheckBox("启用作用域限制");
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        scopePanel.add(enableScopeCheck, gbc);
        
        JLabel protocolLabel = new JLabel("协议:");
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1; gbc.weightx = 0;
        scopePanel.add(protocolLabel, gbc);
        JComboBox<String> protocolCombo = new JComboBox<>(new String[]{"", "http", "https"});
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(protocolCombo, gbc);
        
        JLabel hostLabel = new JLabel("主机名模式:");
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        scopePanel.add(hostLabel, gbc);
        JTextField hostField = new JTextField(hostFromRequest);
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(hostField, gbc);
        
        JLabel pathLabel = new JLabel("路径模式:");
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        scopePanel.add(pathLabel, gbc);
        JTextField pathField = new JTextField();
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(pathField, gbc);
        
        JCheckBox useRegexCheck = new JCheckBox("使用正则表达式");
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        scopePanel.add(useRegexCheck, gbc);
        
        // TTL配置
        JLabel ttlLabel = new JLabel("生存时间(秒):");
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1; gbc.weightx = 0;
        scopePanel.add(ttlLabel, gbc);
        JSpinner ttlSpinner = new JSpinner(new SpinnerNumberModel(3600, 60, 86400, 60));
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(ttlSpinner, gbc);
        
        // 替换策略
        JLabel strategyLabel = new JLabel("替换策略:");
        gbc.gridx = 0; gbc.gridy = 6; gbc.weightx = 0;
        scopePanel.add(strategyLabel, gbc);
        JComboBox<String> strategyCombo = new JComboBox<>(new String[]{"REPLACE", "APPEND", "PREPEND", "UPSERT"});
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(strategyCombo, gbc);
        
        // 优先级
        JLabel priorityLabel = new JLabel("优先级(0-100):");
        gbc.gridx = 0; gbc.gridy = 7; gbc.weightx = 0;
        scopePanel.add(priorityLabel, gbc);
        JSpinner prioritySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 100, 1));
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(prioritySpinner, gbc);
        
        // 禁用/启用作用域字段
        protocolLabel.setEnabled(false);
        protocolCombo.setEnabled(false);
        hostLabel.setEnabled(false);
        hostField.setEnabled(false);
        pathLabel.setEnabled(false);
        pathField.setEnabled(false);
        useRegexCheck.setEnabled(false);
        
        enableScopeCheck.addActionListener(e -> {
            boolean enabled = enableScopeCheck.isSelected();
            protocolLabel.setEnabled(enabled);
            protocolCombo.setEnabled(enabled);
            hostLabel.setEnabled(enabled);
            hostField.setEnabled(enabled);
            pathLabel.setEnabled(enabled);
            pathField.setEnabled(enabled);
            useRegexCheck.setEnabled(enabled);
        });
        
        contentPanel.add(scopePanel, BorderLayout.SOUTH);
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        // 底部按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton submitButton = new JButton("提交");
        submitButton.addActionListener(e -> {
            // 收集选中的Header
            java.util.List<String[]> selectedHeaders = new java.util.ArrayList<>();
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                Boolean selected = (Boolean) tableModel.getValueAt(i, 0);
                if (selected != null && selected) {
                    String name = (String) tableModel.getValueAt(i, 1);
                    String value = (String) tableModel.getValueAt(i, 2);
                    selectedHeaders.add(new String[]{name, value});
                }
            }
            
            if (selectedHeaders.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "请至少选择一个Header字段", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            // 构建作用域配置
            String scopeJson = "null";
            if (enableScopeCheck.isSelected()) {
                String protocol = (String) protocolCombo.getSelectedItem();
                String host = hostField.getText().trim();
                String path = pathField.getText().trim();
                boolean useRegex = useRegexCheck.isSelected();
                
                scopeJson = String.format(
                    "{\"protocol_pattern\":\"%s\",\"host_pattern\":\"%s\",\"path_pattern\":\"%s\",\"use_regex\":%s}",
                    escapeJson(protocol), escapeJson(host), escapeJson(path), useRegex
                );
            }
            
            int ttl = (Integer) ttlSpinner.getValue();
            String strategy = (String) strategyCombo.getSelectedItem();
            int priority = (Integer) prioritySpinner.getValue();
            
            // 发送到后端
            sendSessionHeadersToBackend(selectedHeaders, scopeJson, ttl, strategy, priority);
            dialog.dispose();
        });
        buttonPanel.add(submitButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(cancelButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }
    
    /**
     * 发送会话Header到后端
     */
    private void sendSessionHeadersToBackend(java.util.List<String[]> headers, String scopeJson, 
                                              int ttl, String strategy, int priority) {
        try {
            // 构建JSON payload
            StringBuilder headersArrayJson = new StringBuilder("[");
            for (int i = 0; i < headers.size(); i++) {
                String[] header = headers.get(i);
                if (i > 0) headersArrayJson.append(",");
                headersArrayJson.append(String.format(
                    "{\"header_name\":\"%s\",\"header_value\":\"%s\",\"replace_strategy\":\"%s\",\"priority\":%d,\"is_active\":true,\"ttl\":%d%s}",
                    escapeJson(header[0]),
                    escapeJson(header[1]),
                    strategy,
                    priority,
                    ttl,
                    scopeJson.equals("null") ? "" : ",\"scope\":" + scopeJson
                ));
            }
            headersArrayJson.append("]");
            
            String jsonPayload = "{\"headers\":" + headersArrayJson.toString() + "}";
            
            // 异步发送
            new Thread(() -> {
                try {
                    String response = apiClient.sendSessionHeaders(jsonPayload);
                    
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 已提交 " + headers.size() + " 个会话Header");
                        uiTab.appendLog("    响应: " + response);
                    });
                    
                    stdout.println("[+] Session headers submitted: " + headers.size() + " headers");
                    
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[-] 提交会话Header失败: " + e.getMessage());
                    });
                    stderr.println("[-] Error: " + e.getMessage());
                }
            }).start();
            
        } catch (Exception e) {
            uiTab.appendLog("[-] 构建JSON失败: " + e.getMessage());
            stderr.println("[-] Error: " + e.getMessage());
        }
    }
    
    /**
     * 显示Header规则配置对话框
     */
    private void showHeaderRuleDialog(IHttpRequestResponse requestResponse) {
        JDialog dialog = new JDialog((Frame) null, "提交Header规则", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(900, 750);
        dialog.setLocationRelativeTo(null);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 说明面板
        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder("使用说明"));
        JEditorPane helpPane = new JEditorPane();
        helpPane.setContentType("text/html");
        helpPane.setEditable(false);
        helpPane.setOpaque(false);
        helpPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        helpPane.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        helpPane.setText(
            "<html><body style='font-family:sans-serif;'>" +
            "<b>选择要提交为持久化规则的Header字段</b><br>" +
            "持久化规则将永久保存，并应用于所有匹配的请求<br>" +
            "<span style='color:gray;'>提示: 每个规则需要一个唯一的名称来标识</span>" +
            "</body></html>"
        );
        helpPanel.add(helpPane, BorderLayout.CENTER);
        contentPanel.add(helpPanel, BorderLayout.NORTH);
        
        // 中间部分: Header选择列表
        JPanel headerSelectionPanel = new JPanel(new BorderLayout(5, 5));
        headerSelectionPanel.setBorder(BorderFactory.createTitledBorder("请求Header列表"));
        
        // 提取请求头
        byte[] requestBytes = requestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
        java.util.List<String> headerStrings = requestInfo.getHeaders();
        
        // 解析请求头（跳过第一行请求行）
        java.util.List<String[]> headerItems = new java.util.ArrayList<>();
        for (int i = 1; i < headerStrings.size(); i++) {
            String headerLine = headerStrings.get(i);
            int colonIdx = headerLine.indexOf(':');
            if (colonIdx > 0) {
                String name = headerLine.substring(0, colonIdx).trim();
                String value = headerLine.substring(colonIdx + 1).trim();
                headerItems.add(new String[]{name, value});
            }
        }
        
        // 创建表格模型
        String[] columnNames = {"选择", "Header名称", "Header值"};
        Object[][] tableData = new Object[headerItems.size()][3];
        for (int i = 0; i < headerItems.size(); i++) {
            String headerName = headerItems.get(i)[0];
            String headerValue = headerItems.get(i)[1];
            // Header规则默认不勾选，用户手动选择
            tableData[i] = new Object[]{false, headerName, headerValue};
        }
        
        javax.swing.table.DefaultTableModel tableModel = new javax.swing.table.DefaultTableModel(tableData, columnNames) {
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // 只有复选框可编辑
            }
        };
        
        JTable headerTable = new JTable(tableModel);
        headerTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        headerTable.getColumnModel().getColumn(0).setMaxWidth(60);
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        headerTable.getColumnModel().getColumn(2).setPreferredWidth(400);
        headerTable.setRowHeight(24);
        
        JScrollPane tableScrollPane = new JScrollPane(headerTable);
        headerSelectionPanel.add(tableScrollPane, BorderLayout.CENTER);
        
        // 全选/取消全选按钮
        JPanel tableButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selectAllBtn = new JButton("全选");
        selectAllBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(true, i, 0);
            }
        });
        JButton deselectAllBtn = new JButton("取消全选");
        deselectAllBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(false, i, 0);
            }
        });
        tableButtonPanel.add(selectAllBtn);
        tableButtonPanel.add(deselectAllBtn);
        headerSelectionPanel.add(tableButtonPanel, BorderLayout.SOUTH);
        
        contentPanel.add(headerSelectionPanel, BorderLayout.CENTER);
        
        // 规则配置面板
        JPanel ruleConfigPanel = new JPanel(new GridBagLayout());
        ruleConfigPanel.setBorder(BorderFactory.createTitledBorder("规则配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // 规则名称前缀
        JLabel namePrefixLabel = new JLabel("规则名称前缀:");
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1; gbc.weightx = 0;
        ruleConfigPanel.add(namePrefixLabel, gbc);
        JTextField namePrefixField = new JTextField("Rule_");
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(namePrefixField, gbc);
        
        // 替换策略
        JLabel strategyLabel = new JLabel("替换策略:");
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        ruleConfigPanel.add(strategyLabel, gbc);
        JComboBox<String> strategyCombo = new JComboBox<>(new String[]{"REPLACE", "APPEND", "PREPEND", "UPSERT", "CONDITIONAL"});
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(strategyCombo, gbc);
        
        // 优先级
        JLabel priorityLabel = new JLabel("优先级(0-100):");
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        ruleConfigPanel.add(priorityLabel, gbc);
        JSpinner prioritySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 100, 1));
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(prioritySpinner, gbc);
        
        // 是否启用
        JCheckBox isActiveCheck = new JCheckBox("立即启用规则", true);
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        ruleConfigPanel.add(isActiveCheck, gbc);
        
        // 作用域配置
        JCheckBox enableScopeCheck = new JCheckBox("启用作用域限制");
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        ruleConfigPanel.add(enableScopeCheck, gbc);
        
        // 从请求中提取主机名
        String hostFromRequest = "";
        try {
            hostFromRequest = requestInfo.getUrl().getHost();
        } catch (Exception e) {
            hostFromRequest = "";
        }
        
        JLabel protocolLabel = new JLabel("协议:");
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1; gbc.weightx = 0;
        ruleConfigPanel.add(protocolLabel, gbc);
        JComboBox<String> protocolCombo = new JComboBox<>(new String[]{"", "http", "https"});
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(protocolCombo, gbc);
        
        JLabel hostLabel = new JLabel("主机名模式:");
        gbc.gridx = 0; gbc.gridy = 6; gbc.weightx = 0;
        ruleConfigPanel.add(hostLabel, gbc);
        JTextField hostField = new JTextField(hostFromRequest);
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(hostField, gbc);
        
        JLabel pathLabel = new JLabel("路径模式:");
        gbc.gridx = 0; gbc.gridy = 7; gbc.weightx = 0;
        ruleConfigPanel.add(pathLabel, gbc);
        JTextField pathField = new JTextField();
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(pathField, gbc);
        
        JCheckBox useRegexCheck = new JCheckBox("使用正则表达式");
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 2;
        ruleConfigPanel.add(useRegexCheck, gbc);
        
        // 禁用/启用作用域字段
        protocolLabel.setEnabled(false);
        protocolCombo.setEnabled(false);
        hostLabel.setEnabled(false);
        hostField.setEnabled(false);
        pathLabel.setEnabled(false);
        pathField.setEnabled(false);
        useRegexCheck.setEnabled(false);
        
        enableScopeCheck.addActionListener(e -> {
            boolean enabled = enableScopeCheck.isSelected();
            protocolLabel.setEnabled(enabled);
            protocolCombo.setEnabled(enabled);
            hostLabel.setEnabled(enabled);
            hostField.setEnabled(enabled);
            pathLabel.setEnabled(enabled);
            pathField.setEnabled(enabled);
            useRegexCheck.setEnabled(enabled);
        });
        
        contentPanel.add(ruleConfigPanel, BorderLayout.SOUTH);
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        // 底部按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton submitButton = new JButton("提交");
        submitButton.addActionListener(e -> {
            // 收集选中的Header
            java.util.List<String[]> selectedHeaders = new java.util.ArrayList<>();
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                Boolean selected = (Boolean) tableModel.getValueAt(i, 0);
                if (selected != null && selected) {
                    String name = (String) tableModel.getValueAt(i, 1);
                    String value = (String) tableModel.getValueAt(i, 2);
                    selectedHeaders.add(new String[]{name, value});
                }
            }
            
            if (selectedHeaders.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "请至少选择一个Header字段", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            String namePrefix = namePrefixField.getText().trim();
            if (namePrefix.isEmpty()) {
                namePrefix = "Rule_";
            }
            
            // 构建作用域配置
            String scopeJson = "null";
            if (enableScopeCheck.isSelected()) {
                String protocol = (String) protocolCombo.getSelectedItem();
                String host = hostField.getText().trim();
                String path = pathField.getText().trim();
                boolean useRegex = useRegexCheck.isSelected();
                
                scopeJson = String.format(
                    "{\"protocol_pattern\":\"%s\",\"host_pattern\":\"%s\",\"path_pattern\":\"%s\",\"use_regex\":%s}",
                    escapeJson(protocol), escapeJson(host), escapeJson(path), useRegex
                );
            }
            
            String strategy = (String) strategyCombo.getSelectedItem();
            int priority = (Integer) prioritySpinner.getValue();
            boolean isActive = isActiveCheck.isSelected();
            
            // 发送到后端
            sendHeaderRulesToBackend(selectedHeaders, namePrefix, scopeJson, strategy, priority, isActive);
            dialog.dispose();
        });
        buttonPanel.add(submitButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(cancelButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }
    
    /**
     * 发送Header规则到后端
     */
    private void sendHeaderRulesToBackend(java.util.List<String[]> headers, String namePrefix,
                                          String scopeJson, String strategy, int priority, boolean isActive) {
        // 逐个提交Header规则
        for (int i = 0; i < headers.size(); i++) {
            String[] header = headers.get(i);
            String ruleName = namePrefix + header[0];
            
            try {
                // 构建JSON payload
                StringBuilder jsonBuilder = new StringBuilder("{");
                jsonBuilder.append(String.format("\"name\":\"%s\",", escapeJson(ruleName)));
                jsonBuilder.append(String.format("\"header_name\":\"%s\",", escapeJson(header[0])));
                jsonBuilder.append(String.format("\"header_value\":\"%s\",", escapeJson(header[1])));
                jsonBuilder.append(String.format("\"replace_strategy\":\"%s\",", strategy));
                jsonBuilder.append(String.format("\"priority\":%d,", priority));
                jsonBuilder.append(String.format("\"is_active\":%s", isActive));
                if (!scopeJson.equals("null")) {
                    jsonBuilder.append(",\"scope\":" + scopeJson);
                }
                jsonBuilder.append("}");
                
                String jsonPayload = jsonBuilder.toString();
                
                final String finalRuleName = ruleName;
                final int index = i;
                final int total = headers.size();
                
                // 异步发送
                new Thread(() -> {
                    try {
                        String response = apiClient.sendHeaderRule(jsonPayload);
                        
                        SwingUtilities.invokeLater(() -> {
                            uiTab.appendLog("[+] 已提交Header规则 (" + (index + 1) + "/" + total + "): " + finalRuleName);
                            uiTab.appendLog("    响应: " + response);
                        });
                        
                        stdout.println("[+] Header rule submitted: " + finalRuleName);
                        
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            uiTab.appendLog("[-] 提交Header规则失败: " + finalRuleName + " - " + e.getMessage());
                        });
                        stderr.println("[-] Error: " + e.getMessage());
                    }
                }).start();
                
            } catch (Exception e) {
                uiTab.appendLog("[-] 构建JSON失败: " + e.getMessage());
                stderr.println("[-] Error: " + e.getMessage());
            }
        }
    }
}
