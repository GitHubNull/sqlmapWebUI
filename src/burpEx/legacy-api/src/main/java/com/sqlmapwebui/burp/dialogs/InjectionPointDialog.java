package com.sqlmapwebui.burp.dialogs;

import burp.*;
import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.ScanConfig;
import com.sqlmapwebui.burp.SqlmapApiClient;
import com.sqlmapwebui.burp.SqlmapUITab;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 标记注入点对话框 - Legacy API版本
 */
public class InjectionPointDialog {
    
    @SuppressWarnings("unused")
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final SqlmapApiClient apiClient;
    private final ConfigManager configManager;
    private final SqlmapUITab uiTab;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    
    public InjectionPointDialog(IBurpExtenderCallbacks callbacks, SqlmapApiClient apiClient,
                                 ConfigManager configManager, SqlmapUITab uiTab) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.apiClient = apiClient;
        this.configManager = configManager;
        this.uiTab = uiTab;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
    }
    
    /**
     * 显示标记注入点对话框
     */
    public void show(IHttpRequestResponse requestResponse) {
        JDialog dialog = new JDialog((Frame) null, "标记SQL注入点", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(800, 700);
        dialog.setLocationRelativeTo(null);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 说明标签
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
        
        // 实时更新标记数量
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
    private void sendMarkedRequestToBackend(IHttpRequestResponse requestResponse, String markedRequestText) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            java.net.URL urlObj = requestInfo.getUrl();
            String url = urlObj.toString();
            String host = urlObj.getHost();
            
            // 解析headers和body
            List<String> headersList = new ArrayList<>();
            String body = "";
            
            String[] allLines = markedRequestText.split("\r?\n");
            boolean inBody = false;
            StringBuilder bodyBuilder = new StringBuilder();
            
            for (int i = 0; i < allLines.length; i++) {
                if (!inBody) {
                    if (allLines[i].isEmpty()) {
                        inBody = true;
                    } else {
                        headersList.add(allLines[i]);
                    }
                } else {
                    if (bodyBuilder.length() > 0) {
                        bodyBuilder.append("\n");
                    }
                    bodyBuilder.append(allLines[i]);
                }
            }
            body = bodyBuilder.toString();
            
            // 构建options
            ScanConfig config = configManager.getDefaultConfig().copy();
            Map<String, Object> options = config.toOptionsMap();
            
            // 构建JSON
            StringBuilder headersJson = new StringBuilder("[");
            for (int i = 0; i < headersList.size(); i++) {
                headersJson.append("\"").append(JsonUtils.escapeJson(headersList.get(i))).append("\"");
                if (i < headersList.size() - 1) headersJson.append(",");
            }
            headersJson.append("]");
            
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
                JsonUtils.escapeJson(host),
                headersJson.toString(),
                JsonUtils.escapeJson(body),
                optionsJson.toString()
            );
            
            long markCount = markedRequestText.chars().filter(ch -> ch == '*').count();
            
            // 异步发送
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
}
