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
}
