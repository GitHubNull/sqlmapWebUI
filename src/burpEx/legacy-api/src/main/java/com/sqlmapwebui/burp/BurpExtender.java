package com.sqlmapwebui.burp;

import burp.*;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
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
    
    // UI Components
    private JPanel mainPanel;
    private JTextField serverUrlField;
    private JTextArea logArea;
    private JTable presetConfigTable;
    private DefaultTableModel presetTableModel;
    
    // 默认配置编辑组件
    private JSpinner defaultLevelSpinner;
    private JSpinner defaultRiskSpinner;
    private JComboBox<String> defaultDbmsCombo;
    private JTextField defaultTechniqueField;
    private JCheckBox defaultBatchCheck;
    
    // 连接状态UI组件
    private JLabel connectionStatusLabel;
    private JSpinner maxHistorySpinner;
    
    private static final String EXTENSION_NAME = "SQLMap WebUI";
    private static final String EXTENSION_VERSION = "1.0.0";
    
    private static final String[] DBMS_OPTIONS = {
        "", "MySQL", "PostgreSQL", "Oracle", "Microsoft SQL Server", 
        "SQLite", "MariaDB", "IBM DB2", "Firebird", "SAP MaxDB"
    };
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // 初始化配置管理器
        this.configManager = new ConfigManager(callbacks);
        
        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME + " v" + EXTENSION_VERSION);
        
        // Register context menu factory
        callbacks.registerContextMenuFactory(this);
        
        // Initialize UI
        SwingUtilities.invokeLater(this::initializeUI);
        
        // Add tab to Burp Suite
        callbacks.addSuiteTab(this);
        
        stdout.println("[+] " + EXTENSION_NAME + " v" + EXTENSION_VERSION + " loaded successfully!");
        stdout.println("[+] Backend URL: " + configManager.getBackendUrl());
        stdout.println("[!] 请先测试后端连接，连接成功后才能使用右键菜单功能");
    }
    
    /**
     * Initialize the extension UI panel
     */
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 创建选项卡面板
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Tab 1: 服务器配置
        tabbedPane.addTab("服务器配置", createServerConfigPanel());
        
        // Tab 2: 默认配置
        tabbedPane.addTab("默认配置", createDefaultConfigPanel());
        
        // Tab 3: 常用配置管理
        tabbedPane.addTab("常用配置", createPresetConfigPanel());
        
        // Tab 4: 活动日志
        tabbedPane.addTab("活动日志", createLogPanel());
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // 底部使用说明
        JPanel helpPanel = createHelpPanel();
        mainPanel.add(helpPanel, BorderLayout.SOUTH);
        
        appendLog("扩展已初始化。请先测试后端连接，连接成功后才能提交扫描任务。");
    }
    
    /**
     * 创建服务器配置面板
     */
    private JPanel createServerConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("后端服务器设置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // 后端URL
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("后端URL:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        serverUrlField = new JTextField(configManager.getBackendUrl(), 40);
        formPanel.add(serverUrlField, gbc);
        
        // 连接状态
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("连接状态:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        connectionStatusLabel = new JLabel("● 未连接");
        connectionStatusLabel.setForeground(Color.RED);
        connectionStatusLabel.setFont(connectionStatusLabel.getFont().deriveFont(Font.BOLD));
        formPanel.add(connectionStatusLabel, gbc);
        
        // 历史记录最大数量
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        formPanel.add(new JLabel("历史记录最大数量:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 2;
        JPanel historyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        maxHistorySpinner = new JSpinner(new SpinnerNumberModel(
            configManager.getMaxHistorySize(), 
            ConfigManager.MIN_HISTORY_SIZE, 
            ConfigManager.MAX_HISTORY_SIZE, 1));
        maxHistorySpinner.setPreferredSize(new Dimension(60, 25));
        historyPanel.add(maxHistorySpinner);
        historyPanel.add(new JLabel("  (范围: 3-32条)"));
        formPanel.add(historyPanel, gbc);
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton testButton = new JButton("测试连接");
        testButton.addActionListener(e -> testConnection());
        buttonPanel.add(testButton);
        
        JButton saveButton = new JButton("保存设置");
        saveButton.addActionListener(e -> saveServerConfig());
        buttonPanel.add(saveButton);
        
        gbc.gridx = 1; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(buttonPanel, gbc);
        
        panel.add(formPanel, BorderLayout.NORTH);
        
        // 连接状态信息
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBorder(BorderFactory.createTitledBorder("连接信息"));
        JTextArea statusArea = new JTextArea(5, 40);
        statusArea.setEditable(false);
        statusArea.setText("点击「测试连接」按钮验证与后端服务器的连接。\n\n" +
            "后端服务器应运行在配置的URL上，并提供以下接口：\n" +
            "- POST /burp/admin/scan - 提交扫描任务\n" +
            "- GET /api/version - 获取版本信息");
        statusPanel.add(new JScrollPane(statusArea), BorderLayout.CENTER);
        panel.add(statusPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建默认配置面板
     */
    private JPanel createDefaultConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("默认扫描配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10);
        gbc.anchor = GridBagConstraints.WEST;
        
        ScanConfig defaultConfig = configManager.getDefaultConfig();
        int row = 0;
        
        // Level
        gbc.gridx = 0; gbc.gridy = row;
        formPanel.add(new JLabel("Level (1-5):"), gbc);
        gbc.gridx = 1;
        defaultLevelSpinner = new JSpinner(new SpinnerNumberModel(defaultConfig.getLevel(), 1, 5, 1));
        formPanel.add(defaultLevelSpinner, gbc);
        gbc.gridx = 2;
        formPanel.add(new JLabel("检测级别，越高越全面但越慢"), gbc);
        row++;
        
        // Risk
        gbc.gridx = 0; gbc.gridy = row;
        formPanel.add(new JLabel("Risk (1-3):"), gbc);
        gbc.gridx = 1;
        defaultRiskSpinner = new JSpinner(new SpinnerNumberModel(defaultConfig.getRisk(), 1, 3, 1));
        formPanel.add(defaultRiskSpinner, gbc);
        gbc.gridx = 2;
        formPanel.add(new JLabel("风险级别，越高越危险但检测更全"), gbc);
        row++;
        
        // DBMS
        gbc.gridx = 0; gbc.gridy = row;
        formPanel.add(new JLabel("DBMS:"), gbc);
        gbc.gridx = 1;
        defaultDbmsCombo = new JComboBox<>(DBMS_OPTIONS);
        defaultDbmsCombo.setSelectedItem(defaultConfig.getDbms());
        formPanel.add(defaultDbmsCombo, gbc);
        gbc.gridx = 2;
        formPanel.add(new JLabel("指定数据库类型，留空自动检测"), gbc);
        row++;
        
        // Technique
        gbc.gridx = 0; gbc.gridy = row;
        formPanel.add(new JLabel("Technique:"), gbc);
        gbc.gridx = 1;
        defaultTechniqueField = new JTextField(defaultConfig.getTechnique(), 10);
        formPanel.add(defaultTechniqueField, gbc);
        gbc.gridx = 2;
        formPanel.add(new JLabel("注入技术 (B=布尔, E=报错, U=联合, S=堆叠, T=时间, Q=内联)"), gbc);
        row++;
        
        // Batch
        gbc.gridx = 0; gbc.gridy = row;
        formPanel.add(new JLabel("Batch模式:"), gbc);
        gbc.gridx = 1;
        defaultBatchCheck = new JCheckBox("启用", defaultConfig.isBatch());
        formPanel.add(defaultBatchCheck, gbc);
        gbc.gridx = 2;
        formPanel.add(new JLabel("自动回答所有问题，无需交互"), gbc);
        row++;
        
        // 保存按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveDefaultBtn = new JButton("保存默认配置");
        saveDefaultBtn.addActionListener(e -> saveDefaultConfig());
        buttonPanel.add(saveDefaultBtn);
        
        JButton resetDefaultBtn = new JButton("恢复初始值");
        resetDefaultBtn.addActionListener(e -> resetDefaultConfig());
        buttonPanel.add(resetDefaultBtn);
        
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(buttonPanel, gbc);
        
        panel.add(formPanel, BorderLayout.NORTH);
        
        return panel;
    }
    
    /**
     * 创建常用配置管理面板
     */
    private JPanel createPresetConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 配置表格
        String[] columns = {"名称", "描述", "Level", "Risk", "DBMS", "Technique"};
        presetTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        presetConfigTable = new JTable(presetTableModel);
        presetConfigTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        refreshPresetTable();
        
        JScrollPane scrollPane = new JScrollPane(presetConfigTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("常用配置列表"));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // 操作按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton addBtn = new JButton("添加配置");
        addBtn.addActionListener(e -> showAddPresetDialog());
        buttonPanel.add(addBtn);
        
        JButton editBtn = new JButton("编辑配置");
        editBtn.addActionListener(e -> showEditPresetDialog());
        buttonPanel.add(editBtn);
        
        JButton deleteBtn = new JButton("删除配置");
        deleteBtn.addActionListener(e -> deleteSelectedPreset());
        buttonPanel.add(deleteBtn);
        
        JButton setDefaultBtn = new JButton("设为默认");
        setDefaultBtn.addActionListener(e -> setSelectedAsDefault());
        buttonPanel.add(setDefaultBtn);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建日志面板
     */
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("活动日志"));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        JButton clearLogButton = new JButton("清空日志");
        clearLogButton.addActionListener(e -> logArea.setText(""));
        
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnPanel.add(clearLogButton);
        panel.add(btnPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建帮助面板
     */
    private JPanel createHelpPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createTitledBorder("使用说明"));
        JLabel helpLabel = new JLabel(
            "<html><b>使用步骤:</b><br>" +
            "1. 配置后端URL并点击「测试连接」验证连接<br>" +
            "2. 连接成功后，右键点击HTTP请求选择 '<b>Send to SQLMap WebUI</b>'<br>" +
            "<font color='red'>注意: 必须先测试连接成功，否则右键菜单不会显示!</font></html>"
        );
        panel.add(helpLabel);
        return panel;
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
            
            // 使用默认配置发送
            JMenuItem sendWithDefault = new JMenuItem("Send to SQLMap WebUI");
            sendWithDefault.addActionListener(e -> {
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                if (selectedMessages != null && selectedMessages.length > 0) {
                    for (IHttpRequestResponse message : selectedMessages) {
                        sendRequestToBackend(message, configManager.getDefaultConfig());
                    }
                }
            });
            menuItems.add(sendWithDefault);
            
            // 选择配置发送
            JMenuItem sendWithOptions = new JMenuItem("Send to SQLMap WebUI (选择配置)...");
            sendWithOptions.addActionListener(e -> {
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                if (selectedMessages != null && selectedMessages.length > 0) {
                    showConfigSelectionDialog(selectedMessages[0]);
                }
            });
            menuItems.add(sendWithOptions);
        }
        
        return menuItems;
    }
    
    /**
     * 显示配置选择对话框
     */
    private void showConfigSelectionDialog(IHttpRequestResponse requestResponse) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), 
            "选择扫描配置", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(500, 400);
        dialog.setLocationRelativeTo(mainPanel);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 配置选择列表
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
        
        // 配置预览
        JTextArea previewArea = new JTextArea(6, 40);
        previewArea.setEditable(false);
        previewArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane previewScrollPane = new JScrollPane(previewArea);
        previewScrollPane.setBorder(BorderFactory.createTitledBorder("配置预览"));
        contentPanel.add(previewScrollPane, BorderLayout.SOUTH);
        
        // 选择变化时更新预览
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
        
        // 按钮
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
            
            // 提取body
            int bodyOffset = requestInfo.getBodyOffset();
            String body = "";
            if (bodyOffset < request.length) {
                body = new String(request, bodyOffset, request.length - bodyOffset);
            }
            
            // 构建JSON payload
            StringBuilder headersJson = new StringBuilder("[");
            for (int i = 0; i < headers.size(); i++) {
                headersJson.append("\"").append(escapeJson(headers.get(i))).append("\"");
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
            
            // 发送到后端
            ApiClient apiClient = new ApiClient(configManager.getBackendUrl());
            String response = apiClient.sendTask(jsonPayload);
            
            // 添加到历史记录
            configManager.addToHistory(config);
            
            appendLog("[+] 请求已发送: " + url);
            appendLog("    使用配置: " + config.getName());
            appendLog("    响应: " + response);
            stdout.println("[+] Task created for: " + url);
            
        } catch (Exception e) {
            appendLog("[-] 发送请求失败: " + e.getMessage());
            stderr.println("[-] Error: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }
    
    // ============ 配置操作方法 ============
    
    private void testConnection() {
        try {
            String url = serverUrlField.getText().trim();
            ApiClient apiClient = new ApiClient(url);
            String version = apiClient.getVersion();
            
            // 更新连接状态
            configManager.setConnected(true);
            updateConnectionStatus(true, "已连接 (v" + version + ")");
            
            appendLog("[+] 连接成功! 后端版本: " + version);
            JOptionPane.showMessageDialog(mainPanel,
                "连接成功!\n后端版本: " + version + "\n\n现在可以使用右键菜单发送扫描任务了。",
                "成功", JOptionPane.INFORMATION_MESSAGE);
                
        } catch (Exception e) {
            // 更新连接状态
            configManager.setConnected(false);
            updateConnectionStatus(false, "连接失败");
            
            appendLog("[-] 连接失败: " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel,
                "连接失败: " + e.getMessage(),
                "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void updateConnectionStatus(boolean connected, String text) {
        if (connectionStatusLabel != null) {
            SwingUtilities.invokeLater(() -> {
                connectionStatusLabel.setText("● " + text);
                connectionStatusLabel.setForeground(connected ? new Color(0, 150, 0) : Color.RED);
            });
        }
    }
    
    private void saveServerConfig() {
        String url = serverUrlField.getText().trim();
        configManager.setBackendUrl(url);
        
        // 保存历史记录最大数量
        int maxHistory = (Integer) maxHistorySpinner.getValue();
        configManager.setMaxHistorySize(maxHistory);
        
        // URL变更后需要重新测试连接
        updateConnectionStatus(false, "未连接 (URL已变更，请重新测试)");
        
        appendLog("[+] 服务器配置已保存. URL: " + url + ", 历史记录最大数量: " + maxHistory);
        JOptionPane.showMessageDialog(mainPanel, "配置已保存!\n请点击「测试连接」验证后端可用性。", "成功", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void saveDefaultConfig() {
        ScanConfig config = configManager.getDefaultConfig();
        config.setLevel((Integer) defaultLevelSpinner.getValue());
        config.setRisk((Integer) defaultRiskSpinner.getValue());
        config.setDbms((String) defaultDbmsCombo.getSelectedItem());
        config.setTechnique(defaultTechniqueField.getText().trim());
        config.setBatch(defaultBatchCheck.isSelected());
        
        configManager.setDefaultConfig(config);
        appendLog("[+] 默认配置已保存");
        JOptionPane.showMessageDialog(mainPanel, "默认配置已保存!", "成功", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void resetDefaultConfig() {
        ScanConfig defaultConfig = ScanConfig.createDefault();
        defaultLevelSpinner.setValue(defaultConfig.getLevel());
        defaultRiskSpinner.setValue(defaultConfig.getRisk());
        defaultDbmsCombo.setSelectedItem(defaultConfig.getDbms());
        defaultTechniqueField.setText(defaultConfig.getTechnique());
        defaultBatchCheck.setSelected(defaultConfig.isBatch());
    }
    
    private void refreshPresetTable() {
        presetTableModel.setRowCount(0);
        for (ScanConfig config : configManager.getPresetConfigs()) {
            presetTableModel.addRow(new Object[]{
                config.getName(),
                config.getDescription(),
                config.getLevel(),
                config.getRisk(),
                config.getDbms().isEmpty() ? "自动" : config.getDbms(),
                config.getTechnique().isEmpty() ? "全部" : config.getTechnique()
            });
        }
    }
    
    private void showAddPresetDialog() {
        ScanConfig newConfig = new ScanConfig();
        if (showConfigEditDialog(newConfig, "添加常用配置")) {
            configManager.addPresetConfig(newConfig);
            refreshPresetTable();
            appendLog("[+] 已添加常用配置: " + newConfig.getName());
        }
    }
    
    private void showEditPresetDialog() {
        int selectedRow = presetConfigTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请先选择要编辑的配置", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String name = (String) presetTableModel.getValueAt(selectedRow, 0);
        ScanConfig config = configManager.getPresetConfig(name);
        if (config != null) {
            ScanConfig editConfig = config.copy();
            if (showConfigEditDialog(editConfig, "编辑配置")) {
                configManager.updatePresetConfig(name, editConfig);
                refreshPresetTable();
                appendLog("[+] 已更新配置: " + editConfig.getName());
            }
        }
    }
    
    private void deleteSelectedPreset() {
        int selectedRow = presetConfigTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请先选择要删除的配置", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String name = (String) presetTableModel.getValueAt(selectedRow, 0);
        int confirm = JOptionPane.showConfirmDialog(mainPanel, 
            "确定要删除配置 \"" + name + "\" 吗?", "确认删除", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            configManager.removePresetConfig(name);
            refreshPresetTable();
            appendLog("[+] 已删除配置: " + name);
        }
    }
    
    private void setSelectedAsDefault() {
        int selectedRow = presetConfigTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请先选择要设为默认的配置", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String name = (String) presetTableModel.getValueAt(selectedRow, 0);
        ScanConfig config = configManager.getPresetConfig(name);
        if (config != null) {
            configManager.setDefaultConfig(config.copy());
            appendLog("[+] 已将 \"" + name + "\" 设为默认配置");
            JOptionPane.showMessageDialog(mainPanel, "已设为默认配置!", "成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private boolean showConfigEditDialog(ScanConfig config, String title) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), title, true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(450, 400);
        dialog.setLocationRelativeTo(mainPanel);
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;
        
        // 名称
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("名称:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        JTextField nameField = new JTextField(config.getName(), 20);
        formPanel.add(nameField, gbc);
        row++;
        
        // 描述
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("描述:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        JTextField descField = new JTextField(config.getDescription(), 20);
        formPanel.add(descField, gbc);
        row++;
        
        // Level
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("Level:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        JSpinner levelSpinner = new JSpinner(new SpinnerNumberModel(config.getLevel(), 1, 5, 1));
        formPanel.add(levelSpinner, gbc);
        row++;
        
        // Risk
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("Risk:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        JSpinner riskSpinner = new JSpinner(new SpinnerNumberModel(config.getRisk(), 1, 3, 1));
        formPanel.add(riskSpinner, gbc);
        row++;
        
        // DBMS
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("DBMS:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        JComboBox<String> dbmsCombo = new JComboBox<>(DBMS_OPTIONS);
        dbmsCombo.setSelectedItem(config.getDbms());
        formPanel.add(dbmsCombo, gbc);
        row++;
        
        // Technique
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("Technique:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        JTextField techField = new JTextField(config.getTechnique(), 10);
        formPanel.add(techField, gbc);
        row++;
        
        // Batch
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("Batch:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        JCheckBox batchCheck = new JCheckBox("启用", config.isBatch());
        formPanel.add(batchCheck, gbc);
        
        dialog.add(formPanel, BorderLayout.CENTER);
        
        // 按钮
        final boolean[] result = {false};
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton okButton = new JButton("确定");
        okButton.addActionListener(e -> {
            String name = nameField.getText().trim();
            if (name.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "请输入配置名称", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            config.setName(name);
            config.setDescription(descField.getText().trim());
            config.setLevel((Integer) levelSpinner.getValue());
            config.setRisk((Integer) riskSpinner.getValue());
            config.setDbms((String) dbmsCombo.getSelectedItem());
            config.setTechnique(techField.getText().trim());
            config.setBatch(batchCheck.isSelected());
            result[0] = true;
            dialog.dispose();
        });
        buttonPanel.add(okButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(cancelButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
        
        return result[0];
    }
    
    private void appendLog(String message) {
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> {
                String timestamp = new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
                logArea.append("[" + timestamp + "] " + message + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
    }
    
    private String escapeJson(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
    
    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
