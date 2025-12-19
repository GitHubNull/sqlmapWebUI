package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.PresetConfig;
import com.sqlmapwebui.burp.PresetConfigDatabase;
import com.sqlmapwebui.burp.ScanConfig;
import com.sqlmapwebui.burp.SqlmapApiClient;

import javax.swing.*;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ItemListener;
import java.io.*;
import java.util.List;
import java.util.Properties;
import java.util.function.Consumer;

/**
 * 默认配置面板
 * 管理默认扫描参数
 */
public class DefaultConfigPanel extends BaseConfigPanel {
    
    private static final String CONFIG_FILE_NAME = "sqlmap-webui-config.properties";
    private static final String KEY_SCAN_ARGS_STR = "ScanArgsStr";
    private static final String KEY_SCAN_ARGS_PERSIST = "scan.args.persist";
    
    private JSpinner defaultLevelSpinner;
    private JSpinner defaultRiskSpinner;
    private JComboBox<String> defaultDbmsCombo;
    private JTextField defaultTechniqueField;
    private JCheckBox defaultBatchCheck;
    private JTextField proxyField;
    private JCheckBox forceSSLCheck;
    
    // 注入技术多选框
    private JCheckBox techBCheck;  // B - 布尔型盲注
    private JCheckBox techECheck;  // E - 报错注入
    private JCheckBox techUCheck;  // U - 联合查询
    private JCheckBox techSCheck;  // S - 堆叠查询
    private JCheckBox techTCheck;  // T - 时间盲注
    private JCheckBox techQCheck;  // Q - 内联查询
    
    // 命令行参数预览面板
    private JEditorPane commandPreviewPane;
    
    // 持久化配置
    private JCheckBox persistArgsCheckBox;
    
    // 扫描配置来源选择
    private JRadioButton useDefaultConfigRadio;
    private JRadioButton usePresetConfigRadio;
    private JRadioButton useLastHistoryRadio;
    private JComboBox<String> presetConfigCombo;
    private ButtonGroup configSourceGroup;
    
    // 常用配置数据库引用
    private PresetConfigDatabase presetDatabase;
    
    public DefaultConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient, Consumer<String> logAppender) {
        super(configManager, apiClient, logAppender);
    }
    
    /**
     * 设置常用配置数据库引用
     */
    public void setPresetDatabase(PresetConfigDatabase database) {
        this.presetDatabase = database;
        // 刷新配置列表
        refreshPresetConfigCombo();
        updateRadioButtonStates();
    }
    
    @Override
    protected void initializePanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // ============ 主面板：上下布局 ============
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createTitledBorder("默认扫描配置"));
        
        // ============ 上半部分：左右布局 ============
        JPanel topPanel = new JPanel(new GridLayout(1, 2, 15, 0));
        
        // -------- 左侧：配置参数项 --------
        JPanel leftPanel = createConfigParamsPanel();
        topPanel.add(leftPanel);
        
        // -------- 右侧：扫描配置来源选择 --------
        JPanel rightPanel = createConfigSourcePanel();
        topPanel.add(rightPanel);
        
        mainPanel.add(topPanel, BorderLayout.CENTER);
        
        // ============ 下半部分：按钮面板 ============
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 5));
        
        persistArgsCheckBox = new JCheckBox("参数持久化", true);
        persistArgsCheckBox.setToolTipText("勾选后命令行参数将保存到本地配置文件，下次启动自动加载");
        buttonPanel.add(persistArgsCheckBox);
        
        JButton saveDefaultBtn = new JButton("保存默认配置");
        saveDefaultBtn.addActionListener(e -> saveDefaultConfig());
        buttonPanel.add(saveDefaultBtn);
        
        JButton resetDefaultBtn = new JButton("恢复初始值");
        resetDefaultBtn.addActionListener(e -> resetDefaultConfig());
        buttonPanel.add(resetDefaultBtn);
        
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.NORTH);
        
        // ============ 命令行参数预览面板 ============
        JPanel previewPanel = new JPanel(new BorderLayout());
        previewPanel.setBorder(BorderFactory.createTitledBorder("命令行参数预览"));
        
        commandPreviewPane = new JEditorPane();
        commandPreviewPane.setContentType("text/html");
        commandPreviewPane.setEditable(false);
        commandPreviewPane.setFont(new Font("Consolas", Font.PLAIN, 13));
        commandPreviewPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        
        JScrollPane scrollPane = new JScrollPane(commandPreviewPane);
        scrollPane.setPreferredSize(new Dimension(800, 120));
        previewPanel.add(scrollPane, BorderLayout.CENTER);
        
        add(previewPanel, BorderLayout.CENTER);
        
        // 初始化注入技术选择
        ScanConfig defaultConfig = configManager.getDefaultConfig();
        initTechniqueCheckboxes(defaultConfig.getTechnique());
        
        // 加载持久化配置
        loadPersistedArgs();
        
        // 初始化预览
        updateCommandPreview();
    }
    
    /**
     * 创建配置参数面板（左侧）
     */
    private JPanel createConfigParamsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("扫描参数"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 8, 4, 8);
        gbc.anchor = GridBagConstraints.WEST;
        
        ScanConfig defaultConfig = configManager.getDefaultConfig();
        int row = 0;
        
        // 用于监听变化的监听器
        ChangeListener spinnerListener = e -> updateCommandPreview();
        ItemListener itemListener = e -> updateCommandPreview();
        DocumentListener docListener = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateCommandPreview(); }
            public void removeUpdate(DocumentEvent e) { updateCommandPreview(); }
            public void changedUpdate(DocumentEvent e) { updateCommandPreview(); }
        };
        
        // Level
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Level (1-5):"), gbc);
        gbc.gridx = 1;
        defaultLevelSpinner = new JSpinner(new SpinnerNumberModel(defaultConfig.getLevel(), 1, 5, 1));
        defaultLevelSpinner.addChangeListener(spinnerListener);
        panel.add(defaultLevelSpinner, gbc);
        gbc.gridx = 2;
        panel.add(new JLabel("检测级别"), gbc);
        row++;
        
        // Risk
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Risk (1-3):"), gbc);
        gbc.gridx = 1;
        defaultRiskSpinner = new JSpinner(new SpinnerNumberModel(defaultConfig.getRisk(), 1, 3, 1));
        defaultRiskSpinner.addChangeListener(spinnerListener);
        panel.add(defaultRiskSpinner, gbc);
        gbc.gridx = 2;
        panel.add(new JLabel("风险级别"), gbc);
        row++;
        
        // DBMS
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("DBMS:"), gbc);
        gbc.gridx = 1;
        defaultDbmsCombo = new JComboBox<>(DBMS_OPTIONS);
        defaultDbmsCombo.setSelectedItem(defaultConfig.getDbms());
        defaultDbmsCombo.addItemListener(itemListener);
        panel.add(defaultDbmsCombo, gbc);
        gbc.gridx = 2;
        panel.add(new JLabel("数据库类型"), gbc);
        row++;
        
        // Technique
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Technique:"), gbc);
        gbc.gridx = 1;
        defaultTechniqueField = new JTextField(8);
        defaultTechniqueField.setEditable(false);
        defaultTechniqueField.setEnabled(false);
        defaultTechniqueField.setDisabledTextColor(Color.DARK_GRAY);
        defaultTechniqueField.setToolTipText("通过下方多选框选择注入技术");
        panel.add(defaultTechniqueField, gbc);
        row++;
        
        // 注入技术多选框
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        JPanel techPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        ItemListener techListener = e -> updateTechniqueField();
        
        techBCheck = new JCheckBox("B");
        techBCheck.setToolTipText("Boolean-based blind - 布尔型盲注");
        techBCheck.addItemListener(techListener);
        techPanel.add(techBCheck);
        
        techECheck = new JCheckBox("E");
        techECheck.setToolTipText("Error-based - 报错注入");
        techECheck.addItemListener(techListener);
        techPanel.add(techECheck);
        
        techUCheck = new JCheckBox("U");
        techUCheck.setToolTipText("UNION query-based - 联合查询注入");
        techUCheck.addItemListener(techListener);
        techPanel.add(techUCheck);
        
        techSCheck = new JCheckBox("S");
        techSCheck.setToolTipText("Stacked queries - 堆叠查询注入");
        techSCheck.addItemListener(techListener);
        techPanel.add(techSCheck);
        
        techTCheck = new JCheckBox("T");
        techTCheck.setToolTipText("Time-based blind - 时间盲注");
        techTCheck.addItemListener(techListener);
        techPanel.add(techTCheck);
        
        techQCheck = new JCheckBox("Q");
        techQCheck.setToolTipText("Inline queries - 内联查询注入");
        techQCheck.addItemListener(techListener);
        techPanel.add(techQCheck);
        
        panel.add(techPanel, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Proxy
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("HTTP代理:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        proxyField = new JTextField(defaultConfig.getProxy(), 18);
        proxyField.setToolTipText("HTTP代理地址，如: http://127.0.0.1:8080");
        proxyField.getDocument().addDocumentListener(docListener);
        panel.add(proxyField, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Force SSL
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("强制SSL:"), gbc);
        gbc.gridx = 1;
        forceSSLCheck = new JCheckBox("启用", defaultConfig.isForceSSL());
        forceSSLCheck.setToolTipText("强制使用HTTPS连接测试目标");
        forceSSLCheck.addItemListener(itemListener);
        panel.add(forceSSLCheck, gbc);
        row++;
        
        // Batch
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Batch模式:"), gbc);
        gbc.gridx = 1;
        defaultBatchCheck = new JCheckBox("启用", defaultConfig.isBatch());
        defaultBatchCheck.addItemListener(itemListener);
        panel.add(defaultBatchCheck, gbc);
        
        return panel;
    }
    
    /**
     * 创建扫描配置来源选择面板（右侧）
     */
    private JPanel createConfigSourcePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("右键菜单扫描使用的配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 10, 6, 10);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;
        
        // 配置来源单选组
        configSourceGroup = new ButtonGroup();
        
        // 选项1：使用默认配置
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        useDefaultConfigRadio = new JRadioButton("使用默认配置", true);
        useDefaultConfigRadio.setToolTipText("使用左侧配置的参数进行扫描");
        configSourceGroup.add(useDefaultConfigRadio);
        panel.add(useDefaultConfigRadio, gbc);
        row++;
        
        // 说明文字
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.insets = new Insets(0, 30, 6, 10);
        JLabel defaultDesc = new JLabel("使用左侧配置的参数进行扫描");
        defaultDesc.setForeground(Color.GRAY);
        defaultDesc.setFont(defaultDesc.getFont().deriveFont(11f));
        panel.add(defaultDesc, gbc);
        gbc.insets = new Insets(6, 10, 6, 10);
        row++;
        
        // 选项2：使用常用配置
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        usePresetConfigRadio = new JRadioButton("使用常用配置");
        usePresetConfigRadio.setToolTipText("从常用配置列表中选择一个配置");
        configSourceGroup.add(usePresetConfigRadio);
        usePresetConfigRadio.addItemListener(e -> updatePresetComboState());
        panel.add(usePresetConfigRadio, gbc);
        row++;
        
        // 常用配置下拉框
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.insets = new Insets(0, 30, 6, 10);
        presetConfigCombo = new JComboBox<>();
        presetConfigCombo.setEnabled(false);
        refreshPresetConfigCombo();
        panel.add(presetConfigCombo, gbc);
        gbc.insets = new Insets(6, 10, 6, 10);
        row++;
        
        // 选项3：使用最近历史配置
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        useLastHistoryRadio = new JRadioButton("使用最近历史配置");
        useLastHistoryRadio.setToolTipText("使用最近一次扫描的参数配置");
        configSourceGroup.add(useLastHistoryRadio);
        panel.add(useLastHistoryRadio, gbc);
        row++;
        
        // 历史配置说明
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.insets = new Insets(0, 30, 6, 10);
        JLabel historyDesc = new JLabel("使用最近一次扫描的参数配置");
        historyDesc.setForeground(Color.GRAY);
        historyDesc.setFont(historyDesc.getFont().deriveFont(11f));
        panel.add(historyDesc, gbc);
        gbc.insets = new Insets(6, 10, 6, 10);
        row++;
        
        // 刷新按钮
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        JButton refreshBtn = new JButton("刷新配置列表");
        refreshBtn.addActionListener(e -> {
            refreshPresetConfigCombo();
            updateRadioButtonStates();
            appendLog("[+] 配置列表已刷新");
        });
        panel.add(refreshBtn, gbc);
        
        // 初始化单选按钮状态
        updateRadioButtonStates();
        
        return panel;
    }
    
    /**
     * 刷新常用配置下拉框
     */
    private void refreshPresetConfigCombo() {
        presetConfigCombo.removeAllItems();
        if (presetDatabase != null) {
            List<PresetConfig> presets = presetDatabase.getAllConfigs();
            for (PresetConfig config : presets) {
                presetConfigCombo.addItem(config.getName());
            }
        }
    }
    
    /**
     * 更新常用配置下拉框状态
     */
    private void updatePresetComboState() {
        boolean hasPresets = presetConfigCombo.getItemCount() > 0;
        presetConfigCombo.setEnabled(usePresetConfigRadio.isSelected() && hasPresets);
    }
    
    /**
     * 更新单选按钮状态
     */
    private void updateRadioButtonStates() {
        // 检查常用配置是否有数据（使用PresetConfigDatabase）
        boolean hasPresets = presetDatabase != null && presetDatabase.getCount() > 0;
        usePresetConfigRadio.setEnabled(hasPresets);
        if (!hasPresets && usePresetConfigRadio.isSelected()) {
            useDefaultConfigRadio.setSelected(true);
        }
        
        // 检查历史配置是否有数据
        boolean hasHistory = configManager.getHistoryConfigs().size() > 0;
        useLastHistoryRadio.setEnabled(hasHistory);
        if (!hasHistory && useLastHistoryRadio.isSelected()) {
            useDefaultConfigRadio.setSelected(true);
        }
        
        updatePresetComboState();
    }
    
    /**
     * 获取当前选中的扫描配置
     */
    public ScanConfig getSelectedScanConfig() {
        if (usePresetConfigRadio.isSelected() && presetDatabase != null) {
            String selectedName = (String) presetConfigCombo.getSelectedItem();
            if (selectedName != null) {
                PresetConfig presetConfig = presetDatabase.getConfigByName(selectedName);
                if (presetConfig != null) {
                    // 将PresetConfig的参数字符串转换为ScanConfig
                    ScanConfig config = ScanConfig.createDefault();
                    config.setName(presetConfig.getName());
                    parseArgsToConfig(presetConfig.getParameterString(), config);
                    return config;
                }
            }
        } else if (useLastHistoryRadio.isSelected()) {
            List<ScanConfig> history = configManager.getHistoryConfigs();
            if (!history.isEmpty()) {
                return history.get(0);
            }
        }
        // 默认返回当前配置
        return configManager.getDefaultConfig();
    }
    
    /**
     * 解析参数字符串到ScanConfig
     */
    private void parseArgsToConfig(String argsStr, ScanConfig config) {
        if (argsStr == null || argsStr.isEmpty()) return;
        
        String[] parts = argsStr.split("\\s+");
        for (String part : parts) {
            if (part.startsWith("--level=")) {
                try {
                    config.setLevel(Integer.parseInt(part.substring(8)));
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith("--risk=")) {
                try {
                    config.setRisk(Integer.parseInt(part.substring(7)));
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith("--dbms=")) {
                config.setDbms(part.substring(7));
            } else if (part.startsWith("--technique=")) {
                config.setTechnique(part.substring(12));
            } else if (part.startsWith("--proxy=")) {
                config.setProxy(part.substring(8));
            } else if (part.equals("--force-ssl")) {
                config.setForceSSL(true);
            } else if (part.equals("--batch")) {
                config.setBatch(true);
            }
        }
    }
    
    /**
     * 更新命令行参数预览
     */
    private void updateCommandPreview() {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><style>");
        html.append("body { font-family: Consolas, monospace; font-size: 13px; padding: 10px; line-height: 1.8; }");
        html.append(".param { color: #2980b9; font-weight: bold; }");  // 参数名蓝色
        html.append(".value { color: #27ae60; font-weight: bold; }");  // 参数值绿色
        html.append(".flag { color: #8e44ad; font-weight: bold; }");   // 标志参数紫色
        html.append("</style></head><body>");
        
        int level = (Integer) defaultLevelSpinner.getValue();
        int risk = (Integer) defaultRiskSpinner.getValue();
        String dbms = (String) defaultDbmsCombo.getSelectedItem();
        String technique = defaultTechniqueField.getText().trim();
        String proxy = proxyField.getText().trim();
        boolean forceSSL = forceSSLCheck.isSelected();
        boolean batch = defaultBatchCheck.isSelected();
        
        boolean hasParams = false;
        
        // Level
        if (level != 1) {
            html.append("<span class='param'>--level</span>=<span class='value'>").append(level).append("</span> ");
            hasParams = true;
        }
        
        // Risk
        if (risk != 1) {
            html.append("<span class='param'>--risk</span>=<span class='value'>").append(risk).append("</span> ");
            hasParams = true;
        }
        
        // DBMS
        if (dbms != null && !dbms.isEmpty()) {
            html.append("<span class='param'>--dbms</span>=<span class='value'>").append(escapeHtml(dbms)).append("</span> ");
            hasParams = true;
        }
        
        // Technique
        if (!technique.isEmpty()) {
            html.append("<span class='param'>--technique</span>=<span class='value'>").append(escapeHtml(technique)).append("</span> ");
            hasParams = true;
        }
        
        // Proxy
        if (!proxy.isEmpty()) {
            html.append("<span class='param'>--proxy</span>=<span class='value'>").append(escapeHtml(proxy)).append("</span> ");
            hasParams = true;
        }
        
        // Force SSL
        if (forceSSL) {
            html.append("<span class='flag'>--force-ssl</span> ");
            hasParams = true;
        }
        
        // Batch
        if (batch) {
            html.append("<span class='flag'>--batch</span> ");
            hasParams = true;
        }
        
        if (!hasParams) {
            html.append("<span style='color: gray;'>（使用默认参数，无额外命令行选项）</span>");
        }
        
        html.append("</body></html>");
        
        commandPreviewPane.setText(html.toString());
        commandPreviewPane.setCaretPosition(0);
    }
    
    /**
     * HTML转义
     */
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
    
    /**
     * 初始化注入技术多选框
     */
    private void initTechniqueCheckboxes(String technique) {
        if (technique == null) technique = "";
        String upper = technique.toUpperCase();
        
        techBCheck.setSelected(upper.contains("B"));
        techECheck.setSelected(upper.contains("E"));
        techUCheck.setSelected(upper.contains("U"));
        techSCheck.setSelected(upper.contains("S"));
        techTCheck.setSelected(upper.contains("T"));
        techQCheck.setSelected(upper.contains("Q"));
        
        updateTechniqueField();
    }
    
    /**
     * 根据多选框状态更新注入技术输入框
     */
    private void updateTechniqueField() {
        StringBuilder sb = new StringBuilder();
        
        if (techBCheck.isSelected()) sb.append("B");
        if (techECheck.isSelected()) sb.append("E");
        if (techUCheck.isSelected()) sb.append("U");
        if (techSCheck.isSelected()) sb.append("S");
        if (techTCheck.isSelected()) sb.append("T");
        if (techQCheck.isSelected()) sb.append("Q");
        
        defaultTechniqueField.setText(sb.toString());
        updateCommandPreview();
    }
    
    private void saveDefaultConfig() {
        ScanConfig config = configManager.getDefaultConfig();
        config.setLevel((Integer) defaultLevelSpinner.getValue());
        config.setRisk((Integer) defaultRiskSpinner.getValue());
        config.setDbms((String) defaultDbmsCombo.getSelectedItem());
        config.setTechnique(defaultTechniqueField.getText().trim());
        config.setProxy(proxyField.getText().trim());
        config.setForceSSL(forceSSLCheck.isSelected());
        config.setBatch(defaultBatchCheck.isSelected());
        
        configManager.setDefaultConfig(config);
        
        // 保存持久化配置
        savePersistedArgs();
        
        appendLog("[+] 默认配置已保存");
        
        String persistMsg = persistArgsCheckBox.isSelected() ? 
            "<p><b>持久化:</b> 已保存到本地配置文件</p>" : 
            "<p><b>持久化:</b> 未启用</p>";
        
        HtmlMessageDialog.showInfo(this, "保存成功", 
            "<h3 style='color: green;'>✓ 默认配置已保存</h3>" +
            "<p><b>命令行参数:</b> " + buildArgsString() + "</p>" +
            persistMsg);
    }
    
    private void resetDefaultConfig() {
        ScanConfig defaultConfig = ScanConfig.createDefault();
        defaultLevelSpinner.setValue(defaultConfig.getLevel());
        defaultRiskSpinner.setValue(defaultConfig.getRisk());
        defaultDbmsCombo.setSelectedItem(defaultConfig.getDbms());
        
        // 重置注入技术多选框
        initTechniqueCheckboxes(defaultConfig.getTechnique());
        
        proxyField.setText(defaultConfig.getProxy());
        forceSSLCheck.setSelected(defaultConfig.isForceSSL());
        defaultBatchCheck.setSelected(defaultConfig.isBatch());
        persistArgsCheckBox.setSelected(true);
        
        updateCommandPreview();
        appendLog("[+] 已恢复为默认配置");
    }
    
    /**
     * 生成命令行参数字符串
     */
    private String buildArgsString() {
        StringBuilder sb = new StringBuilder();
        
        int level = (Integer) defaultLevelSpinner.getValue();
        int risk = (Integer) defaultRiskSpinner.getValue();
        String dbms = (String) defaultDbmsCombo.getSelectedItem();
        String technique = defaultTechniqueField.getText().trim();
        String proxy = proxyField.getText().trim();
        boolean forceSSL = forceSSLCheck.isSelected();
        boolean batch = defaultBatchCheck.isSelected();
        
        if (level != 1) {
            sb.append("--level=").append(level).append(" ");
        }
        if (risk != 1) {
            sb.append("--risk=").append(risk).append(" ");
        }
        if (dbms != null && !dbms.isEmpty()) {
            sb.append("--dbms=").append(dbms).append(" ");
        }
        if (!technique.isEmpty()) {
            sb.append("--technique=").append(technique).append(" ");
        }
        if (!proxy.isEmpty()) {
            sb.append("--proxy=").append(proxy).append(" ");
        }
        if (forceSSL) {
            sb.append("--force-ssl ");
        }
        if (batch) {
            sb.append("--batch ");
        }
        
        return sb.toString().trim();
    }
    
    /**
     * 从配置文件加载持久化的命令行参数
     */
    private void loadPersistedArgs() {
        File configFile = getConfigFile();
        if (!configFile.exists()) {
            return;
        }
        
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configFile);
             InputStreamReader reader = new InputStreamReader(fis, "UTF-8")) {
            props.load(reader);
            
            // 读取持久化状态
            String persistStr = props.getProperty(KEY_SCAN_ARGS_PERSIST);
            if (persistStr != null) {
                persistArgsCheckBox.setSelected(Boolean.parseBoolean(persistStr));
            }
            
            // 读取命令行参数字符串
            String argsStr = props.getProperty(KEY_SCAN_ARGS_STR);
            if (argsStr != null && !argsStr.isEmpty()) {
                parseArgsString(argsStr);
                appendLog("[+] 已加载持久化的命令行参数: " + argsStr);
            }
        } catch (IOException e) {
            appendLog("[-] 读取持久化配置失败: " + e.getMessage());
        }
    }
    
    /**
     * 解析命令行参数字符串并设置到UI
     */
    private void parseArgsString(String argsStr) {
        String[] parts = argsStr.split("\\s+");
        for (String part : parts) {
            if (part.startsWith("--level=")) {
                try {
                    int level = Integer.parseInt(part.substring(8));
                    if (level >= 1 && level <= 5) {
                        defaultLevelSpinner.setValue(level);
                    }
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith("--risk=")) {
                try {
                    int risk = Integer.parseInt(part.substring(7));
                    if (risk >= 1 && risk <= 3) {
                        defaultRiskSpinner.setValue(risk);
                    }
                } catch (NumberFormatException ignored) {}
            } else if (part.startsWith("--dbms=")) {
                String dbms = part.substring(7);
                defaultDbmsCombo.setSelectedItem(dbms);
            } else if (part.startsWith("--technique=")) {
                String technique = part.substring(12).toUpperCase();
                initTechniqueCheckboxes(technique);
            } else if (part.startsWith("--proxy=")) {
                String proxy = part.substring(8);
                proxyField.setText(proxy);
            } else if (part.equals("--force-ssl")) {
                forceSSLCheck.setSelected(true);
            } else if (part.equals("--batch")) {
                defaultBatchCheck.setSelected(true);
            }
        }
    }
    
    /**
     * 保存命令行参数到配置文件
     */
    private void savePersistedArgs() {
        File configFile = getConfigFile();
        
        // 读取现有配置
        Properties props = new Properties();
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile);
                 InputStreamReader reader = new InputStreamReader(fis, "UTF-8")) {
                props.load(reader);
            } catch (IOException e) {
                appendLog("[-] 读取配置文件失败: " + e.getMessage());
            }
        }
        
        // 更新持久化状态
        props.setProperty(KEY_SCAN_ARGS_PERSIST, String.valueOf(persistArgsCheckBox.isSelected()));
        
        // 如果启用持久化，保存命令行参数
        if (persistArgsCheckBox.isSelected()) {
            props.setProperty(KEY_SCAN_ARGS_STR, buildArgsString());
        } else {
            props.remove(KEY_SCAN_ARGS_STR);
        }
        
        // 写入文件
        try (FileOutputStream fos = new FileOutputStream(configFile);
             OutputStreamWriter writer = new OutputStreamWriter(fos, "UTF-8")) {
            props.store(writer, "SQLMap WebUI Burp Extension Configuration");
            if (persistArgsCheckBox.isSelected()) {
                appendLog("[+] 命令行参数已持久化保存: " + buildArgsString());
            }
        } catch (IOException e) {
            appendLog("[-] 保存配置文件失败: " + e.getMessage());
            HtmlMessageDialog.showError(this, "错误", "保存配置文件失败: " + e.getMessage());
        }
    }
    
    /**
     * 获取配置文件路径
     */
    private File getConfigFile() {
        String userDir = System.getProperty("user.dir");
        return new File(userDir, CONFIG_FILE_NAME);
    }
}
