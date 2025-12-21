package com.sqlmapwebui.burp.dialogs;

import burp.*;
import com.sqlmapwebui.burp.*;
import com.sqlmapwebui.burp.panels.GuidedParamEditor;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 高级扫描配置对话框 - Legacy API版本
 * 整合：
 * 1. 配置选择（历史配置、默认配置、常用配置）
 * 2. 引导式扫描配置（参数搜索和命令行预览）
 * 3. 注入点标记功能（仅对纯文本报文有效，多选时需满足数量限制）
 */
public class AdvancedScanConfigDialog {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final SqlmapApiClient apiClient;
    private final ConfigManager configManager;
    private final SqlmapUITab uiTab;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    
    // UI组件
    private JDialog dialog;
    private JTabbedPane tabbedPane;
    
    // 配置选择Tab
    private JList<ConfigManager.ConfigOption> configList;
    private DefaultListModel<ConfigManager.ConfigOption> configListModel;
    private JTextArea configPreviewArea;
    private JCheckBox useDefaultCheck;
    
    // 引导式配置Tab
    private GuidedParamEditor guidedEditor;
    
    // 注入点标记Tab
    private JTabbedPane injectionTabPane;
    private List<JTextArea> requestEditors = new ArrayList<>();
    private List<JLabel> markCountLabels = new ArrayList<>();
    private JTable requestTable;
    private DefaultTableModel requestTableModel;
    private TableRowSorter<DefaultTableModel> tableRowSorter;
    private JTextField searchField;
    private JTextArea currentRequestEditor;
    private JLabel currentMarkCountLabel;
    private int currentSelectedIndex = -1;
    
    // 请求数据
    private List<IHttpRequestResponse> textMessages;
    private List<IHttpRequestResponse> binaryMessages;
    private boolean showInjectionMarkTab = false;
    
    // 当前选择的配置
    private ScanConfig currentConfig;
    
    public AdvancedScanConfigDialog(IBurpExtenderCallbacks callbacks, SqlmapApiClient apiClient,
                                     ConfigManager configManager, SqlmapUITab uiTab,
                                     IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.apiClient = apiClient;
        this.configManager = configManager;
        this.uiTab = uiTab;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
    }
    
    /**
     * 显示对话框（单个请求）
     */
    public void show(IHttpRequestResponse requestResponse) {
        List<IHttpRequestResponse> singleList = new ArrayList<>();
        singleList.add(requestResponse);
        show(singleList, new ArrayList<>());
    }
    
    /**
     * 显示对话框（多个请求，已过滤）
     */
    public void show(List<IHttpRequestResponse> textMessages, List<IHttpRequestResponse> binaryMessages) {
        this.textMessages = textMessages;
        this.binaryMessages = binaryMessages;
        
        // 检查是否显示注入点标记Tab
        int maxCount = configManager.getMaxInjectionMarkCount();
        showInjectionMarkTab = textMessages.size() > 0 && textMessages.size() <= maxCount;
        
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
        for (IHttpRequestResponse msg : binaryMessages) {
            IRequestInfo reqInfo = helpers.analyzeRequest(msg);
            String url = reqInfo.getUrl().toString();
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
        dialog = new JDialog((Frame) null, "Send to SQLMap WebUI (配置扫描)", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(900, 700);
        dialog.setLocationRelativeTo(null);
        
        // 顶部信息栏
        JPanel infoPanel = createInfoPanel();
        dialog.add(infoPanel, BorderLayout.NORTH);
        
        // 主内容区
        tabbedPane = new JTabbedPane();
        
        // Tab 1: 配置选择
        JPanel configSelectPanel = createConfigSelectPanel();
        tabbedPane.addTab("选择配置", configSelectPanel);
        
        // Tab 2: 引导式配置
        JPanel guidedConfigPanel = createGuidedConfigPanel();
        tabbedPane.addTab("引导式配置", guidedConfigPanel);
        
        // Tab 3: 注入点标记（条件性显示）
        if (showInjectionMarkTab) {
            JPanel injectionPanel = createInjectionMarkPanel();
            tabbedPane.addTab("标记注入点 (*)", injectionPanel);
        }
        
        dialog.add(tabbedPane, BorderLayout.CENTER);
        
        // 底部按钮
        JPanel buttonPanel = createButtonPanel();
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        // 初始化当前配置
        currentConfig = configManager.getDefaultConfig().copy();
    }
    
    /**
     * 创建信息面板
     */
    private JPanel createInfoPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        
        StringBuilder info = new StringBuilder();
        info.append("待扫描请求: ").append(textMessages.size()).append(" 个纯文本报文");
        if (!binaryMessages.isEmpty()) {
            info.append(" (已过滤 ").append(binaryMessages.size()).append(" 个二进制报文)");
        }
        
        JLabel infoLabel = new JLabel(info.toString());
        infoLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        panel.add(infoLabel, BorderLayout.WEST);
        
        // 第一个URL预览
        if (!textMessages.isEmpty()) {
            IRequestInfo reqInfo = helpers.analyzeRequest(textMessages.get(0));
            String firstUrl = reqInfo.getUrl().toString();
            if (firstUrl.length() > 80) {
                firstUrl = firstUrl.substring(0, 77) + "...";
            }
            JLabel urlLabel = new JLabel(firstUrl);
            urlLabel.setForeground(Color.GRAY);
            urlLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            panel.add(urlLabel, BorderLayout.SOUTH);
        }
        
        return panel;
    }
    
    /**
     * 创建配置选择面板
     */
    private JPanel createConfigSelectPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 左侧：配置列表
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        leftPanel.setBorder(BorderFactory.createTitledBorder("可选配置"));
        leftPanel.setPreferredSize(new Dimension(280, 400));
        
        // 默认配置复选框
        useDefaultCheck = new JCheckBox("使用默认配置 (推荐)", true);
        useDefaultCheck.addActionListener(e -> {
            configList.setEnabled(!useDefaultCheck.isSelected());
            if (useDefaultCheck.isSelected()) {
                configList.clearSelection();
                currentConfig = configManager.getDefaultConfig().copy();
                updateConfigPreview(currentConfig);
            }
        });
        leftPanel.add(useDefaultCheck, BorderLayout.NORTH);
        
        // 配置列表
        configListModel = new DefaultListModel<>();
        for (ConfigManager.ConfigOption option : configManager.getAllConfigOptions()) {
            configListModel.addElement(option);
        }
        
        configList = new JList<>(configListModel);
        configList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        configList.setCellRenderer(new ConfigOptionRenderer());
        configList.setEnabled(false);
        
        configList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                ConfigManager.ConfigOption selected = configList.getSelectedValue();
                if (selected != null && !selected.isSeparator() && selected.getConfig() != null) {
                    currentConfig = selected.getConfig().copy();
                    updateConfigPreview(currentConfig);
                }
            }
        });
        
        JScrollPane listScrollPane = new JScrollPane(configList);
        leftPanel.add(listScrollPane, BorderLayout.CENTER);
        
        panel.add(leftPanel, BorderLayout.WEST);
        
        // 右侧：配置预览
        JPanel rightPanel = new JPanel(new BorderLayout(5, 5));
        rightPanel.setBorder(BorderFactory.createTitledBorder("配置详情"));
        
        configPreviewArea = new JTextArea();
        configPreviewArea.setEditable(false);
        configPreviewArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        JScrollPane previewScrollPane = new JScrollPane(configPreviewArea);
        rightPanel.add(previewScrollPane, BorderLayout.CENTER);
        
        panel.add(rightPanel, BorderLayout.CENTER);
        
        // 初始化预览
        updateConfigPreview(configManager.getDefaultConfig());
        
        return panel;
    }
    
    /**
     * 创建引导式配置面板
     */
    private JPanel createGuidedConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // 使用现有的GuidedParamEditor
        guidedEditor = new GuidedParamEditor();
        guidedEditor.setOnChangeCallback(() -> {
            // 当参数变化时，更新当前配置
            updateConfigFromGuided();
        });
        
        panel.add(guidedEditor, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建注入点标记面板
     */
    private JPanel createInjectionMarkPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 顶部：可折叠的使用说明（默认收起）
        JPanel helpPanel = createCollapsibleHelpPanel();
        panel.add(helpPanel, BorderLayout.NORTH);
        
        // 中间：左右分栏布局
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(280);
        splitPane.setResizeWeight(0.3);
        
        // 左侧：请求列表表格
        JPanel leftPanel = createRequestListPanel();
        splitPane.setLeftComponent(leftPanel);
        
        // 右侧：报文编辑区
        JPanel rightPanel = createRequestEditorPanel();
        splitPane.setRightComponent(rightPanel);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        // 延迟初始化选中第一个请求（确保 UI 完全初始化后）
        SwingUtilities.invokeLater(() -> {
            if (requestTable.getRowCount() > 0) {
                requestTable.setRowSelectionInterval(0, 0);
                currentSelectedIndex = 0;
                loadRequestToEditor(0);
            }
        });
        
        return panel;
    }
    
    /**
     * 创建可折叠的使用说明面板（默认收起）
     */
    private JPanel createCollapsibleHelpPanel() {
        JPanel wrapper = new JPanel(new BorderLayout());
        
        // 说明内容面板
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
        
        // 展开/收起按钮
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
            wrapper.revalidate();
        });
        
        // 超过上限提示
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.add(toggleBtn, BorderLayout.WEST);
        
        int maxCount = configManager.getMaxInjectionMarkCount();
        int totalCount = textMessages.size();
        if (totalCount > maxCount) {
            JLabel warningLabel = new JLabel(
                String.format("⚠ 已选 %d 个报文，超过标记上限 %d，仅前 %d 个支持注入点标记", 
                    totalCount, maxCount, maxCount));
            warningLabel.setForeground(new Color(200, 100, 0));
            warningLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            headerPanel.add(warningLabel, BorderLayout.EAST);
        }
        
        wrapper.add(headerPanel, BorderLayout.NORTH);
        wrapper.add(helpContent, BorderLayout.CENTER);
        
        return wrapper;
    }
    
    /**
     * 创建请求列表面板（左侧）
     */
    private JPanel createRequestListPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("请求列表"));
        panel.setPreferredSize(new Dimension(280, 400));
        
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
            IHttpRequestResponse msg = textMessages.get(i);
            IRequestInfo reqInfo = helpers.analyzeRequest(msg);
            String method = reqInfo.getMethod();
            String path = reqInfo.getUrl().getPath();
            if (path.length() > 40) {
                path = path.substring(0, 37) + "...";
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
        requestTable.getColumnModel().getColumn(2).setPreferredWidth(140);
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
                    "可在默认配置标签页调整此限制 (3-5)。");
                currentRequestEditor.setEditable(false);
                currentRequestEditor.setBackground(new Color(245, 245, 245));
                currentMarkCountLabel.setText("标记数: -");
                currentMarkCountLabel.setForeground(Color.GRAY);
            } else {
                // 从缓存加载或原始请求
                if (index < requestEditors.size() && requestEditors.get(index) != null) {
                    currentRequestEditor.setText(requestEditors.get(index).getText());
                } else {
                    IHttpRequestResponse msg = textMessages.get(index);
                    String requestText = new String(msg.getRequest());
                    currentRequestEditor.setText(requestText);
                    // 缓存
                    while (requestEditors.size() <= index) {
                        requestEditors.add(null);
                    }
                    JTextArea cached = new JTextArea(requestText);
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
        // 只在有有效选中且未超限时保存
        if (currentSelectedIndex >= 0 && currentSelectedIndex < maxCount && 
            currentSelectedIndex < textMessages.size() && currentRequestEditor != null) {
            String content = currentRequestEditor.getText();
            if (content == null || content.isEmpty()) {
                return; // 不保存空内容
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
     * 发送扫描
     */
    private void sendScan() {
        int currentTab = tabbedPane.getSelectedIndex();
        
        // 获取当前使用的配置
        ScanConfig config = getCurrentConfig();
        
        if (showInjectionMarkTab && currentTab == 2) {
            // 使用注入点标记发送
            sendWithInjectionMarks(config);
        } else {
            // 使用常规配置发送
            sendNormalScan(config);
        }
        
        dialog.dispose();
    }
    
    /**
     * 获取当前配置
     */
    private ScanConfig getCurrentConfig() {
        int currentTab = tabbedPane.getSelectedIndex();
        
        if (currentTab == 0) {
            // 配置选择Tab
            if (useDefaultCheck.isSelected()) {
                return configManager.getDefaultConfig().copy();
            }
            ConfigManager.ConfigOption selected = configList.getSelectedValue();
            if (selected != null && selected.getConfig() != null) {
                return selected.getConfig().copy();
            }
            return configManager.getDefaultConfig().copy();
        } else if (currentTab == 1) {
            // 引导式配置Tab
            updateConfigFromGuided();
            return currentConfig;
        } else {
            // 注入点标记Tab - 使用默认配置
            return configManager.getDefaultConfig().copy();
        }
    }
    
    /**
     * 从引导式编辑器更新配置
     */
    private void updateConfigFromGuided() {
        if (guidedEditor != null) {
            String cmdLine = guidedEditor.getCommandLine();
            if (cmdLine != null && !cmdLine.trim().isEmpty()) {
                // 解析命令行参数到配置
                ParseResult result = ScanConfigParser.parse(cmdLine);
                if (result.isSuccess() && result.getConfig() != null) {
                    currentConfig = result.getConfig();
                }
            }
        }
    }
    
    /**
     * 常规扫描发送
     */
    private void sendNormalScan(ScanConfig config) {
        for (IHttpRequestResponse msg : textMessages) {
            sendRequestToBackend(msg, config);
        }
    }
    
    /**
     * 带注入点标记的发送
     */
    private void sendWithInjectionMarks(ScanConfig config) {
        // 保存当前编辑器内容
        saveCurrentEditorContent();
        
        int maxCount = configManager.getMaxInjectionMarkCount();
        int sendCount = Math.min(textMessages.size(), maxCount);
        
        for (int i = 0; i < sendCount; i++) {
            IHttpRequestResponse msg = textMessages.get(i);
            String markedRequest = "";
            
            // 从缓存中获取编辑后的内容
            if (i < requestEditors.size() && requestEditors.get(i) != null) {
                markedRequest = requestEditors.get(i).getText();
            } else {
                markedRequest = new String(msg.getRequest());
            }
            
            // 检查是否有标记
            if (!markedRequest.contains("*")) {
                // 无标记，询问用户
                int confirm = JOptionPane.showConfirmDialog(dialog,
                    "请求 " + (i + 1) + " 未检测到注入点标记 (*)，确定要继续吗？\nsqlmap将自动检测所有参数。",
                    "确认", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (confirm != JOptionPane.YES_OPTION) {
                    continue;
                }
            }
            
            sendMarkedRequest(msg, markedRequest, config);
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
            String host = requestInfo.getUrl().getHost();
            List<String> headers = requestInfo.getHeaders();
            
            int bodyOffset = requestInfo.getBodyOffset();
            String body = "";
            if (bodyOffset < request.length) {
                body = new String(request, bodyOffset, request.length - bodyOffset);
            }
            
            // 构建JSON payload
            StringBuilder headersJson = new StringBuilder("[");
            for (int i = 0; i < headers.size(); i++) {
                headersJson.append("\"").append(JsonUtils.escapeJson(headers.get(i))).append("\"");
                if (i < headers.size() - 1) headersJson.append(",");
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
     * 发送带标记的请求
     */
    private void sendMarkedRequest(IHttpRequestResponse requestResponse, String markedRequestText, ScanConfig config) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            String url = requestInfo.getUrl().toString();
            String host = requestInfo.getUrl().getHost();
            
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
                    
                    configManager.addToHistory(config);
                    
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 已发送带标记的请求: " + url);
                        uiTab.appendLog("    注入点标记数: " + markCount);
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
     * 更新配置预览
     */
    private void updateConfigPreview(ScanConfig config) {
        if (configPreviewArea != null && config != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("名称: ").append(config.getName()).append("\n");
            sb.append("描述: ").append(config.getDescription() != null ? config.getDescription() : "-").append("\n");
            sb.append("Level: ").append(config.getLevel()).append("\n");
            sb.append("Risk: ").append(config.getRisk()).append("\n");
            sb.append("DBMS: ").append(config.getDbms().isEmpty() ? "自动检测" : config.getDbms()).append("\n");
            sb.append("Technique: ").append(config.getTechnique().isEmpty() ? "全部" : config.getTechnique()).append("\n");
            sb.append("Batch: ").append(config.isBatch() ? "是" : "否").append("\n");
            
            // 命令行预览
            sb.append("\n--- 命令行参数 ---\n");
            Map<String, Object> options = config.toOptionsMap();
            for (Map.Entry<String, Object> entry : options.entrySet()) {
                sb.append("--").append(entry.getKey());
                if (entry.getValue() != null && !entry.getValue().toString().equals("true")) {
                    sb.append("=").append(entry.getValue());
                }
                sb.append("\n");
            }
            
            configPreviewArea.setText(sb.toString());
            configPreviewArea.setCaretPosition(0);
        }
    }
    
    /**
     * 获取短URL
     */
    private String getShortUrl(String url, int maxLen) {
        if (url == null) return "";
        if (url.length() <= maxLen) return url;
        return url.substring(0, maxLen - 3) + "...";
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
                    setEnabled(list.isEnabled());
                }
            }
            return this;
        }
    }
}
