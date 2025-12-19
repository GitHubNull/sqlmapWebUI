package com.sqlmapwebui.burp;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.function.Consumer;

/**
 * UI Tab for SQLMap WebUI Extension (Montoya API)
 * 
 * 功能：
 * 1. 服务器配置
 * 2. 默认扫描配置
 * 3. 常用配置管理
 * 4. 活动日志
 */
public class SqlmapUITab extends JPanel {
    
    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final ConfigManager configManager;
    private final Consumer<String> onBackendUrlChange;
    
    // UI Components
    private JTextField serverUrlField;
    private JTextArea logArea;
    private JLabel statusLabel;
    private JTable presetConfigTable;
    private DefaultTableModel presetTableModel;
    
    // 默认配置编辑组件
    private JSpinner defaultLevelSpinner;
    private JSpinner defaultRiskSpinner;
    private JComboBox<String> defaultDbmsCombo;
    private JTextField defaultTechniqueField;
    private JCheckBox defaultBatchCheck;
    
    private static final String[] DBMS_OPTIONS = {
        "", "MySQL", "PostgreSQL", "Oracle", "Microsoft SQL Server", 
        "SQLite", "MariaDB", "IBM DB2", "Firebird", "SAP MaxDB"
    };
    
    public SqlmapUITab(MontoyaApi api, SqlmapApiClient apiClient, 
                       ConfigManager configManager, Consumer<String> onBackendUrlChange) {
        this.api = api;
        this.apiClient = apiClient;
        this.configManager = configManager;
        this.onBackendUrlChange = onBackendUrlChange;
        
        initializeUI();
    }
    
    /**
     * Initialize the UI components
     */
    private void initializeUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Header panel
        JPanel headerPanel = createHeaderPanel();
        add(headerPanel, BorderLayout.NORTH);
        
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
        
        add(tabbedPane, BorderLayout.CENTER);
        
        // Footer panel
        JPanel footerPanel = createFooterPanel();
        add(footerPanel, BorderLayout.SOUTH);
    }
    
    /**
     * Create header panel with title and status
     */
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        
        JLabel titleLabel = new JLabel("SQLMap WebUI Extension (Montoya API)");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 18));
        panel.add(titleLabel, BorderLayout.WEST);
        
        statusLabel = new JLabel("● Disconnected");
        statusLabel.setForeground(Color.RED);
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        panel.add(statusLabel, BorderLayout.EAST);
        
        return panel;
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
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton testButton = new JButton("测试连接");
        testButton.addActionListener(e -> testConnection());
        buttonPanel.add(testButton);
        
        JButton saveButton = new JButton("保存设置");
        saveButton.addActionListener(e -> saveServerConfig());
        buttonPanel.add(saveButton);
        
        gbc.gridx = 1; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
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
     * Create log panel
     */
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(200, 200, 200));
        logArea.setCaretColor(Color.WHITE);
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("活动日志"));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Log controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton clearLogButton = new JButton("清空日志");
        clearLogButton.addActionListener(e -> logArea.setText(""));
        controlPanel.add(clearLogButton);
        
        panel.add(controlPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * Create footer panel with help info
     */
    private JPanel createFooterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("使用说明"));
        
        JLabel helpLabel = new JLabel(
            "<html>" +
            "<b>快速开始:</b><br>" +
            "1. 配置后端URL并测试连接<br>" +
            "2. 在Burp Suite中右键点击任意HTTP请求<br>" +
            "3. 选择 '<b>Send to SQLMap WebUI</b>' 使用默认配置发送<br>" +
            "4. 或选择 '<b>Send to SQLMap WebUI (选择配置)...</b>' 选择常用/历史配置发送<br>" +
            "5. 在SQLMap WebUI前端查看扫描结果" +
            "</html>"
        );
        helpLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.add(helpLabel, BorderLayout.CENTER);
        
        return panel;
    }
    
    // ============ 配置操作方法 ============
    
    private void testConnection() {
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                String url = serverUrlField.getText().trim();
                apiClient.setBaseUrl(url);
                return apiClient.getVersion();
            }
            
            @Override
            protected void done() {
                try {
                    String version = get();
                    appendLog("[+] 连接成功! 后端版本: " + version);
                    updateStatus(true, "Connected (v" + version + ")");
                    
                    JOptionPane.showMessageDialog(SqlmapUITab.this,
                        "连接成功!\n后端版本: " + version,
                        "成功",
                        JOptionPane.INFORMATION_MESSAGE);
                        
                } catch (Exception e) {
                    appendLog("[-] 连接失败: " + e.getMessage());
                    updateStatus(false, "Disconnected");
                    
                    JOptionPane.showMessageDialog(SqlmapUITab.this,
                        "连接失败: " + e.getMessage(),
                        "错误",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }
    
    private void saveServerConfig() {
        String url = serverUrlField.getText().trim();
        configManager.setBackendUrl(url);
        onBackendUrlChange.accept(url);
        appendLog("[+] 服务器配置已保存. URL: " + url);
        
        JOptionPane.showMessageDialog(this,
            "配置已保存!",
            "成功",
            JOptionPane.INFORMATION_MESSAGE);
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
        JOptionPane.showMessageDialog(this, "默认配置已保存!", "成功", JOptionPane.INFORMATION_MESSAGE);
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
            JOptionPane.showMessageDialog(this, "请先选择要编辑的配置", "提示", JOptionPane.WARNING_MESSAGE);
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
            JOptionPane.showMessageDialog(this, "请先选择要删除的配置", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String name = (String) presetTableModel.getValueAt(selectedRow, 0);
        int confirm = JOptionPane.showConfirmDialog(this, 
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
            JOptionPane.showMessageDialog(this, "请先选择要设为默认的配置", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String name = (String) presetTableModel.getValueAt(selectedRow, 0);
        ScanConfig config = configManager.getPresetConfig(name);
        if (config != null) {
            configManager.setDefaultConfig(config.copy());
            appendLog("[+] 已将 \"" + name + "\" 设为默认配置");
            JOptionPane.showMessageDialog(this, "已设为默认配置!", "成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private boolean showConfigEditDialog(ScanConfig config, String title) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), title, true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(450, 400);
        dialog.setLocationRelativeTo(this);
        
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
    
    /**
     * Update status label
     */
    private void updateStatus(boolean connected, String text) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("● " + text);
            statusLabel.setForeground(connected ? new Color(0, 150, 0) : Color.RED);
        });
    }
    
    /**
     * Append message to log area
     */
    public void appendLog(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")
            ) + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    /**
     * 获取配置管理器
     */
    public ConfigManager getConfigManager() {
        return configManager;
    }
}
