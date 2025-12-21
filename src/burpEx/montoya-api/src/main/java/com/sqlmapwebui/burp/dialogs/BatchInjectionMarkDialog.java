package com.sqlmapwebui.burp.dialogs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlmapwebui.burp.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 批量注入点标记对话框
 * 支持多选报文的批量注入点标记
 * 采用双栏布局：左侧报文列表表格，右侧编辑区
 */
public class BatchInjectionMarkDialog {
    
    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final ConfigManager configManager;
    private final SqlmapUITab uiTab;
    
    // UI组件
    private JDialog dialog;
    private JTable requestTable;
    private DefaultTableModel requestTableModel;
    private TableRowSorter<DefaultTableModel> tableRowSorter;
    private JTextField searchField;
    private JTextArea currentRequestEditor;
    private JLabel currentMarkCountLabel;
    private int currentSelectedIndex = -1;
    
    // 请求数据
    private List<HttpRequestResponse> textMessages;
    private List<HttpRequestResponse> binaryMessages;
    private List<JTextArea> requestEditors = new ArrayList<>();
    
    public BatchInjectionMarkDialog(MontoyaApi api, SqlmapApiClient apiClient,
                                     ConfigManager configManager, SqlmapUITab uiTab) {
        this.api = api;
        this.apiClient = apiClient;
        this.configManager = configManager;
        this.uiTab = uiTab;
    }
    
    /**
     * 显示对话框（单个请求）
     */
    public void show(HttpRequestResponse requestResponse) {
        List<HttpRequestResponse> singleList = new ArrayList<>();
        singleList.add(requestResponse);
        show(singleList, new ArrayList<>());
    }
    
    /**
     * 显示对话框（多个请求）
     */
    public void show(List<HttpRequestResponse> textMessages, List<HttpRequestResponse> binaryMessages) {
        this.textMessages = textMessages;
        this.binaryMessages = binaryMessages;
        
        // 显示二进制报文警告
        if (configManager.isShowBinaryWarning() && !binaryMessages.isEmpty()) {
            showBinaryWarningDialog();
        }
        
        createDialog();
        dialog.setVisible(true);
    }
    
    /**
     * 显示二进制报文警告
     */
    private void showBinaryWarningDialog() {
        StringBuilder sb = new StringBuilder();
        sb.append("以下报文包含二进制数据，不支持扫描：\n\n");
        for (HttpRequestResponse msg : binaryMessages) {
            String url = msg.request().url();
            if (url.length() > 60) {
                url = url.substring(0, 57) + "...";
            }
            sb.append("• ").append(url).append("\n");
        }
        JOptionPane.showMessageDialog(null, sb.toString(), 
            "二进制报文警告", JOptionPane.WARNING_MESSAGE);
    }
    
    /**
     * 创建对话框
     */
    private void createDialog() {
        dialog = new JDialog((Frame) null, "标记注入点并扫描 (*)", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(950, 700);
        dialog.setLocationRelativeTo(null);
        
        // 顶部信息栏和可折叠说明
        JPanel topPanel = createTopPanel();
        dialog.add(topPanel, BorderLayout.NORTH);
        
        // 主内容区：左右分栏布局
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.35);
        splitPane.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        
        // 左侧：请求列表表格
        JPanel leftPanel = createRequestListPanel();
        splitPane.setLeftComponent(leftPanel);
        
        // 右侧：报文编辑区
        JPanel rightPanel = createRequestEditorPanel();
        splitPane.setRightComponent(rightPanel);
        
        dialog.add(splitPane, BorderLayout.CENTER);
        
        // 底部按钮
        JPanel buttonPanel = createButtonPanel();
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        // 延迟初始化选中第一个请求
        SwingUtilities.invokeLater(() -> {
            if (requestTable.getRowCount() > 0) {
                requestTable.setRowSelectionInterval(0, 0);
                currentSelectedIndex = 0;
                loadRequestToEditor(0);
            }
        });
    }
    
    /**
     * 创建顶部面板（信息栏 + 可折叠说明）
     */
    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        
        // 信息行
        JPanel infoRow = new JPanel(new BorderLayout());
        
        // 左侧统计信息
        int maxCount = configManager.getMaxInjectionMarkCount();
        int textCount = textMessages.size();
        int editableCount = Math.min(textCount, maxCount);
        
        StringBuilder infoText = new StringBuilder();
        infoText.append("待标记请求: ").append(textCount).append(" 个纯文本报文");
        if (!binaryMessages.isEmpty()) {
            infoText.append(" (已过滤 ").append(binaryMessages.size()).append(" 个二进制报文)");
        }
        
        JLabel infoLabel = new JLabel(infoText.toString());
        infoLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        infoRow.add(infoLabel, BorderLayout.WEST);
        
        // 右侧：超限警告（如果超过上限）
        if (textCount > maxCount) {
            JPanel warningPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
            
            JLabel warningLabel = new JLabel(
                String.format("⚠ 超过标记上限，仅前 %d 个可标记", maxCount));
            warningLabel.setForeground(new Color(200, 100, 0));
            warningLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            warningPanel.add(warningLabel);
            
            // 问号图标按钮
            JButton helpBtn = new JButton("?");
            helpBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
            helpBtn.setMargin(new Insets(0, 4, 0, 4));
            helpBtn.setToolTipText(String.format(
                "选中的纯文本报文数量(%d)超过标记上限(%d)，仅前%d个报文可进行注入点标记", 
                textCount, maxCount, maxCount));
            helpBtn.addActionListener(e -> showLimitExplanation(textCount, maxCount));
            warningPanel.add(helpBtn);
            
            infoRow.add(warningPanel, BorderLayout.EAST);
        }
        
        panel.add(infoRow, BorderLayout.NORTH);
        
        // 可折叠的使用说明
        JPanel helpWrapper = new JPanel(new BorderLayout());
        
        JPanel helpContent = new JPanel(new BorderLayout());
        helpContent.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
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
            "<span style='color:gray;'>提示: 可标记多个注入点，sqlmap会依次测试</span>" +
            "</body></html>"
        );
        helpContent.add(helpPane, BorderLayout.CENTER);
        helpContent.setVisible(false); // 默认收起
        
        JButton toggleBtn = new JButton("▶ 使用说明");
        toggleBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        toggleBtn.setBorderPainted(false);
        toggleBtn.setContentAreaFilled(false);
        toggleBtn.setFocusPainted(false);
        toggleBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        toggleBtn.setHorizontalAlignment(SwingConstants.LEFT);
        toggleBtn.addActionListener(e -> {
            boolean visible = !helpContent.isVisible();
            helpContent.setVisible(visible);
            toggleBtn.setText(visible ? "▼ 使用说明" : "▶ 使用说明");
            helpWrapper.revalidate();
        });
        
        helpWrapper.add(toggleBtn, BorderLayout.NORTH);
        helpWrapper.add(helpContent, BorderLayout.CENTER);
        panel.add(helpWrapper, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 显示限制说明对话框
     */
    private void showLimitExplanation(int selectedCount, int maxCount) {
        String message = String.format(
            "选中报文数量超过标记上限\n\n" +
            "当前选中: %d 个纯文本报文\n" +
            "标记上限: %d 个\n" +
            "可标记数: 前 %d 个\n\n" +
            "限制原因:\n" +
            "• 批量标记注入点需要手动编辑每个报文\n" +
            "• 过多报文会导致界面操作复杂度增加\n" +
            "• 建议分批进行注入点标记测试\n\n" +
            "调整方法:\n" +
            "在扩展的\"默认配置\"标签页中，\n" +
            "可调整\"注入点标记数量限制\"(范围 3-15)",
            selectedCount, maxCount, maxCount);
        
        JOptionPane.showMessageDialog(dialog, message, 
            "标记数量限制说明", JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 创建请求列表面板（左侧）
     */
    private JPanel createRequestListPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("请求列表"));
        panel.setPreferredSize(new Dimension(300, 400));
        
        // 搜索框
        JPanel searchPanel = new JPanel(new BorderLayout(5, 0));
        searchPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        searchField = new JTextField();
        searchField.setToolTipText("输入关键字过滤请求");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filterTable(); }
            public void removeUpdate(DocumentEvent e) { filterTable(); }
            public void changedUpdate(DocumentEvent e) { filterTable(); }
        });
        searchPanel.add(new JLabel("搜索: "), BorderLayout.WEST);
        searchPanel.add(searchField, BorderLayout.CENTER);
        panel.add(searchPanel, BorderLayout.NORTH);
        
        // 请求表格
        String[] columnNames = {"#", "方法", "URL/Path", "标记数"};
        requestTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 3) return Integer.class;
                return String.class;
            }
        };
        
        // 填充表格数据
        int maxCount = configManager.getMaxInjectionMarkCount();
        for (int i = 0; i < textMessages.size(); i++) {
            HttpRequestResponse msg = textMessages.get(i);
            HttpRequest request = msg.request();
            String method = request.method();
            String path = request.path();
            if (path.length() > 35) {
                path = path.substring(0, 32) + "...";
            }
            // 超过上限的显示标记
            boolean overLimit = i >= maxCount;
            String displayPath = overLimit ? path + " (超限)" : path;
            requestTableModel.addRow(new Object[]{i + 1, method, displayPath, 0});
        }
        
        requestTable = new JTable(requestTableModel);
        requestTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestTable.setAutoCreateRowSorter(true);
        tableRowSorter = new TableRowSorter<>(requestTableModel);
        requestTable.setRowSorter(tableRowSorter);
        
        // 设置列宽（可拖动调整）
        requestTable.getColumnModel().getColumn(0).setPreferredWidth(35);
        requestTable.getColumnModel().getColumn(0).setMinWidth(30);
        requestTable.getColumnModel().getColumn(1).setPreferredWidth(55);
        requestTable.getColumnModel().getColumn(1).setMinWidth(40);
        requestTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        requestTable.getColumnModel().getColumn(2).setMinWidth(80);
        requestTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        requestTable.getColumnModel().getColumn(3).setMinWidth(50);
        
        // 选择事件
        requestTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = requestTable.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = requestTable.convertRowIndexToModel(viewRow);
                    saveCurrentEditorContent();
                    loadRequestToEditor(modelRow);
                }
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(requestTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // 统计信息
        int total = textMessages.size();
        int editable = Math.min(total, maxCount);
        JLabel statsLabel = new JLabel(String.format("共 %d 个请求，%d 个可标记", total, editable));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        statsLabel.setForeground(Color.GRAY);
        panel.add(statsLabel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建请求编辑面板（右侧）
     */
    private JPanel createRequestEditorPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("报文编辑"));
        
        // 编辑区
        currentRequestEditor = new JTextArea();
        currentRequestEditor.setFont(new Font("Monospaced", Font.PLAIN, 12));
        currentRequestEditor.setLineWrap(false);
        
        JScrollPane scrollPane = new JScrollPane(currentRequestEditor);
        scrollPane.setRowHeaderView(new TextLineNumber(currentRequestEditor));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // 工具栏
        JPanel toolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton insertMarkBtn = new JButton("插入标记 (*)");
        insertMarkBtn.addActionListener(e -> {
            int pos = currentRequestEditor.getCaretPosition();
            currentRequestEditor.insert("*", pos);
            currentRequestEditor.requestFocus();
            updateCurrentMarkCount();
        });
        toolPanel.add(insertMarkBtn);
        
        JButton clearMarksBtn = new JButton("清除所有标记");
        clearMarksBtn.addActionListener(e -> {
            String text = currentRequestEditor.getText();
            currentRequestEditor.setText(text.replace("*", ""));
            updateCurrentMarkCount();
        });
        toolPanel.add(clearMarksBtn);
        
        currentMarkCountLabel = new JLabel("标记数: 0");
        toolPanel.add(Box.createHorizontalStrut(20));
        toolPanel.add(currentMarkCountLabel);
        
        // 实时更新标记数量
        currentRequestEditor.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateCurrentMarkCount(); }
            public void removeUpdate(DocumentEvent e) { updateCurrentMarkCount(); }
            public void changedUpdate(DocumentEvent e) { updateCurrentMarkCount(); }
        });
        
        panel.add(toolPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建按钮面板
     */
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        JButton sendButton = new JButton("发送扫描");
        sendButton.addActionListener(e -> sendScan());
        panel.add(sendButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        panel.add(cancelButton);
        
        return panel;
    }
    
    /**
     * 过滤表格
     */
    private void filterTable() {
        String text = searchField.getText().trim().toLowerCase();
        if (text.isEmpty()) {
            tableRowSorter.setRowFilter(null);
        } else {
            tableRowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
        }
    }
    
    /**
     * 加载请求到编辑器
     */
    private void loadRequestToEditor(int index) {
        int maxCount = configManager.getMaxInjectionMarkCount();
        currentSelectedIndex = index;
        
        if (index >= 0 && index < textMessages.size()) {
            // 检查是否超过上限
            if (index >= maxCount) {
                currentRequestEditor.setText("此请求超过标记上限 (" + maxCount + ")\n\n" +
                    "仅前 " + maxCount + " 个请求支持注入点标记。\n" +
                    "可在默认配置标签页调整此限制 (3-15)。");
                currentRequestEditor.setEditable(false);
                currentRequestEditor.setBackground(new Color(245, 245, 245));
                currentMarkCountLabel.setText("标记数: -");
                currentMarkCountLabel.setForeground(Color.GRAY);
            } else {
                // 从缓存加载或原始请求
                if (index < requestEditors.size() && requestEditors.get(index) != null) {
                    currentRequestEditor.setText(requestEditors.get(index).getText());
                } else {
                    HttpRequestResponse msg = textMessages.get(index);
                    currentRequestEditor.setText(msg.request().toString());
                    // 缓存
                    while (requestEditors.size() <= index) {
                        requestEditors.add(null);
                    }
                    JTextArea cached = new JTextArea(msg.request().toString());
                    requestEditors.set(index, cached);
                }
                currentRequestEditor.setEditable(true);
                currentRequestEditor.setBackground(Color.WHITE);
                updateCurrentMarkCount();
            }
            currentRequestEditor.setCaretPosition(0);
        }
    }
    
    /**
     * 保存当前编辑器内容
     */
    private void saveCurrentEditorContent() {
        int maxCount = configManager.getMaxInjectionMarkCount();
        if (currentSelectedIndex >= 0 && currentSelectedIndex < maxCount && 
            currentSelectedIndex < textMessages.size() && currentRequestEditor != null) {
            String content = currentRequestEditor.getText();
            if (content == null || content.isEmpty()) {
                return;
            }
            while (requestEditors.size() <= currentSelectedIndex) {
                requestEditors.add(null);
            }
            if (requestEditors.get(currentSelectedIndex) == null) {
                requestEditors.set(currentSelectedIndex, new JTextArea());
            }
            requestEditors.get(currentSelectedIndex).setText(content);
            
            // 更新表格中的标记数
            long count = content.chars().filter(ch -> ch == '*').count();
            requestTableModel.setValueAt((int) count, currentSelectedIndex, 3);
        }
    }
    
    /**
     * 更新当前标记数
     */
    private void updateCurrentMarkCount() {
        String text = currentRequestEditor.getText();
        long count = text.chars().filter(ch -> ch == '*').count();
        currentMarkCountLabel.setText("标记数: " + count);
        currentMarkCountLabel.setForeground(count > 0 ? new Color(0, 150, 0) : Color.GRAY);
        
        // 更新表格
        int maxCount = configManager.getMaxInjectionMarkCount();
        if (currentSelectedIndex >= 0 && currentSelectedIndex < maxCount) {
            requestTableModel.setValueAt((int) count, currentSelectedIndex, 3);
        }
    }
    
    /**
     * 发送扫描
     */
    private void sendScan() {
        // 保存当前编辑器内容
        saveCurrentEditorContent();
        
        int maxCount = configManager.getMaxInjectionMarkCount();
        int sendCount = Math.min(textMessages.size(), maxCount);
        
        // 获取右键菜单使用的配置
        ScanConfig config = configManager.getDefaultConfig().copy();
        
        for (int i = 0; i < sendCount; i++) {
            HttpRequestResponse msg = textMessages.get(i);
            String markedRequest = "";
            
            // 从缓存中获取编辑后的内容
            if (i < requestEditors.size() && requestEditors.get(i) != null) {
                markedRequest = requestEditors.get(i).getText();
            } else {
                markedRequest = msg.request().toString();
            }
            
            // 检查是否有标记
            if (!markedRequest.contains("*")) {
                int confirm = JOptionPane.showConfirmDialog(dialog,
                    "请求 " + (i + 1) + " 未检测到注入点标记 (*)，确定要继续吗？\nsqlmap将自动检测所有参数。",
                    "确认", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (confirm != JOptionPane.YES_OPTION) {
                    continue;
                }
            }
            
            sendMarkedRequest(msg.request(), markedRequest, config);
        }
        
        dialog.dispose();
    }
    
    /**
     * 发送带标记的请求
     */
    private void sendMarkedRequest(HttpRequest originalRequest, String markedRequestText, ScanConfig config) {
        try {
            String url = originalRequest.url();
            String host = "";
            try {
                java.net.URL urlObj = new java.net.URL(url);
                host = urlObj.getHost();
            } catch (Exception e) {
                host = "unknown";
            }
            
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
                    
                    api.logging().logToOutput("[+] Task created with " + markCount + " injection point(s) for: " + url);
                    
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
