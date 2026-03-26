package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.SqlmapApiClient;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.*;
import java.util.Properties;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * 服务器配置面板
 * 管理后端服务器IP、端口和连接设置
 * 支持配置持久化到本地文件
 */
public class ServerConfigPanel extends BaseConfigPanel {
    
    private static final String CONFIG_FILE_NAME = "sqlmap-webui-config.properties";
    private static final String KEY_SERVER_IP = "server.ip";
    private static final String KEY_SERVER_PORT = "server.port";
    private static final String KEY_MAX_HISTORY = "max.history";
    private static final String KEY_PERSIST_CONFIG = "persist.config";
    
    // IP地址验证正则（支持域名和IP）
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^(localhost|" +
        "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|" +
        "([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z]{2,})$"
    );
    
    private final Consumer<String> onBackendUrlChange;
    private final Consumer<Boolean> onConnectionStatusChange;
    
    private JTextField serverIpField;
    private JTextField serverPortField;
    private JSpinner maxHistorySpinner;
    private JCheckBox persistConfigCheckBox;
    private JLabel ipValidationLabel;
    private JLabel portValidationLabel;
    
    // 临时目录配置组件
    private JTextField tempDirField;
    private JLabel tempDirStatusLabel;
    private JButton tempDirSaveBtn;
    private JButton tempDirResetBtn;
    
    public ServerConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient,
                             Consumer<String> logAppender, Consumer<String> onBackendUrlChange,
                             Consumer<Boolean> onConnectionStatusChange) {
        super(configManager, apiClient, logAppender);
        this.onBackendUrlChange = onBackendUrlChange;
        this.onConnectionStatusChange = onConnectionStatusChange;
    }
    
    @Override
    protected void initializePanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 主面板
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        
        // 服务器配置表单
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("后端服务器设置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        
        int row = 0;
        
        // 服务器IP地址
        gbc.gridx = 0; gbc.gridy = row;
        formPanel.add(new JLabel("服务器地址:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JPanel ipPanel = new JPanel(new BorderLayout(5, 0));
        serverIpField = new JTextField(20);
        serverIpField.setToolTipText("输入服务器IP地址或域名，如: localhost, 127.0.0.1, example.com");
        ipPanel.add(serverIpField, BorderLayout.CENTER);
        ipValidationLabel = new JLabel();
        ipValidationLabel.setPreferredSize(new Dimension(20, 20));
        ipPanel.add(ipValidationLabel, BorderLayout.EAST);
        formPanel.add(ipPanel, gbc);
        
        // IP字段失去焦点时验证
        serverIpField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                validateIpField();
            }
        });
        row++;
        
        // 服务器端口
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("服务器端口:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JPanel portPanel = new JPanel(new BorderLayout(5, 0));
        serverPortField = new JTextField(8);
        serverPortField.setToolTipText("输入端口号 (1-65535)，默认: 8775");
        portPanel.add(serverPortField, BorderLayout.CENTER);
        portValidationLabel = new JLabel();
        portValidationLabel.setPreferredSize(new Dimension(20, 20));
        portPanel.add(portValidationLabel, BorderLayout.EAST);
        // 填充剩余空间
        portPanel.add(Box.createHorizontalGlue(), BorderLayout.EAST);
        formPanel.add(portPanel, gbc);
        
        // 端口字段失去焦点时验证
        serverPortField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                validatePortField();
            }
        });
        row++;
        
        // 历史记录最大数量
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("历史记录最大数量:"), gbc);
        
        gbc.gridx = 1;
        JPanel historyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        maxHistorySpinner = new JSpinner(new SpinnerNumberModel(
            configManager.getMaxHistorySize(), 
            ConfigManager.MIN_HISTORY_SIZE, 
            ConfigManager.MAX_HISTORY_SIZE, 1));
        maxHistorySpinner.setPreferredSize(new Dimension(60, 25));
        historyPanel.add(maxHistorySpinner);
        historyPanel.add(new JLabel("  (范围: 3-32条)"));
        formPanel.add(historyPanel, gbc);
        row++;
        
        // 持久化配置选项
        gbc.gridx = 0; gbc.gridy = row;
        formPanel.add(new JLabel("配置持久化:"), gbc);
        
        gbc.gridx = 1;
        JPanel persistPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        persistConfigCheckBox = new JCheckBox("启用本地配置文件持久化", true);
        persistConfigCheckBox.setToolTipText("勾选后配置将保存到本地文件，下次启动自动加载");
        persistPanel.add(persistConfigCheckBox);
        formPanel.add(persistPanel, gbc);
        row++;
        
        // 按钮面板
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        
        JButton testButton = new JButton("测试连接");
        testButton.addActionListener(e -> testConnection());
        buttonPanel.add(testButton);
        
        JButton saveButton = new JButton("保存设置");
        saveButton.addActionListener(e -> saveServerConfig());
        buttonPanel.add(saveButton);
        
        JButton resetButton = new JButton("重置为默认");
        resetButton.addActionListener(e -> resetToDefault());
        buttonPanel.add(resetButton);
        
        formPanel.add(buttonPanel, gbc);
        
        mainPanel.add(formPanel, BorderLayout.NORTH);
        
        // 临时目录配置面板
        JPanel tempDirPanel = createTempDirConfigPanel();
        
        // 将两个配置面板放到一个垂直布局的容器中
        JPanel configContainer = new JPanel();
        configContainer.setLayout(new BoxLayout(configContainer, BoxLayout.Y_AXIS));
        configContainer.add(formPanel);
        configContainer.add(Box.createVerticalStrut(10));
        configContainer.add(tempDirPanel);
        
        mainPanel.add(configContainer, BorderLayout.NORTH);
        
        // 使用说明面板（使用HTML格式）
        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), 
            "使用说明", 
            TitledBorder.LEFT, 
            TitledBorder.TOP
        ));
        
        JEditorPane helpPane = new JEditorPane();
        helpPane.setContentType("text/html");
        helpPane.setEditable(false);
        helpPane.setOpaque(false);
        helpPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        helpPane.setFont(new Font("SansSerif", Font.PLAIN, 12));
        helpPane.setText(createHelpContent());
        helpPane.setCaretPosition(0);
        
        JScrollPane helpScrollPane = new JScrollPane(helpPane);
        helpScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        helpScrollPane.setPreferredSize(new Dimension(600, 280));
        helpPanel.add(helpScrollPane, BorderLayout.CENTER);
        
        mainPanel.add(helpPanel, BorderLayout.CENTER);
        
        add(mainPanel, BorderLayout.CENTER);
        
        // 加载配置
        loadConfiguration();
    }
    
    /**
     * 创建HTML格式的帮助内容
     */
    private String createHelpContent() {
        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 5px; }" +
            "h3 { color: #2c3e50; margin: 10px 0 5px 0; border-bottom: 1px solid #bdc3c7; padding-bottom: 3px; }" +
            "h4 { color: #34495e; margin: 8px 0 3px 0; }" +
            "ul { margin: 3px 0 8px 20px; padding: 0; }" +
            "li { margin: 2px 0; }" +
            ".highlight { color: #e74c3c; font-weight: bold; }" +
            ".success { color: #27ae60; }" +
            ".info { color: #3498db; }" +
            ".code { font-family: 'Consolas', monospace; background: #ecf0f1; padding: 1px 4px; border-radius: 3px; }" +
            ".warning { background: #fff3cd; padding: 5px; border-left: 3px solid #ffc107; margin: 5px 0; }" +
            "</style></head><body>" +
            
            "<h3>🚀 快速开始</h3>" +
            "<ol>" +
            "<li><b>配置服务器</b>：填写后端服务的IP地址和端口号</li>" +
            "<li><b>测试连接</b>：点击「测试连接」按钮验证服务器可用性</li>" +
            "<li><b>发送请求</b>：在Burp的任意HTTP请求上右键，选择 <span class='code'>Send to SQLMap WebUI</span></li>" +
            "</ol>" +
            
            "<h3>⚙️ 配置说明</h3>" +
            "<h4>服务器地址</h4>" +
            "<ul>" +
            "<li>支持IP地址格式：<span class='code'>127.0.0.1</span>、<span class='code'>192.168.1.100</span></li>" +
            "<li>支持域名格式：<span class='code'>localhost</span>、<span class='code'>example.com</span></li>" +
            "</ul>" +
            
            "<h4>服务器端口</h4>" +
            "<ul>" +
            "<li>有效范围：<span class='code'>1 - 65535</span></li>" +
            "<li>默认端口：<span class='code'>8775</span>（SQLMap WebUI后端默认端口）</li>" +
            "</ul>" +
            
            "<h4>配置持久化</h4>" +
            "<ul>" +
            "<li>勾选后，配置将保存到 <span class='code'>" + CONFIG_FILE_NAME + "</span> 文件</li>" +
            "<li>文件位置：Burp Suite运行目录</li>" +
            "<li>下次启动Burp时自动加载已保存的配置</li>" +
            "</ul>" +
            
            "<h3>🔌 后端API接口</h3>" +
            "<ul>" +
            "<li><span class='code'>POST /burp/admin/scan</span> - 提交SQL注入扫描任务</li>" +
            "<li><span class='code'>GET /api/version</span> - 获取后端版本信息</li>" +
            "<li><span class='code'>GET /api/tasks</span> - 获取任务列表</li>" +
            "</ul>" +
            
            "<div class='warning'>" +
            "<b>⚠️ 重要提示：</b>必须先测试连接成功，右键菜单「Send to SQLMap WebUI」才会显示！" +
            "</div>" +
            
            "<h3>📋 右键菜单功能</h3>" +
            "<ul>" +
            "<li><b>Send to SQLMap WebUI</b> - 使用默认配置发送扫描</li>" +
            "<li><b>Send to SQLMap WebUI (选择配置)...</b> - 选择特定配置发送</li>" +
            "<li><b>标记注入点并扫描 (*)</b> - 手动标记注入点后发送</li>" +
            "</ul>" +
            
            "</body></html>";
    }
    
    /**
     * 验证IP地址字段
     */
    private boolean validateIpField() {
        String ip = serverIpField.getText().trim();
        if (ip.isEmpty()) {
            setValidationIcon(ipValidationLabel, false, "IP地址不能为空");
            return false;
        }
        
        if (!IP_PATTERN.matcher(ip).matches()) {
            setValidationIcon(ipValidationLabel, false, "无效的IP地址或域名格式");
            return false;
        }
        
        setValidationIcon(ipValidationLabel, true, "格式正确");
        return true;
    }
    
    /**
     * 验证端口字段
     */
    private boolean validatePortField() {
        String portStr = serverPortField.getText().trim();
        if (portStr.isEmpty()) {
            setValidationIcon(portValidationLabel, false, "端口不能为空");
            return false;
        }
        
        try {
            int port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) {
                setValidationIcon(portValidationLabel, false, "端口范围: 1-65535");
                return false;
            }
            setValidationIcon(portValidationLabel, true, "格式正确");
            return true;
        } catch (NumberFormatException e) {
            setValidationIcon(portValidationLabel, false, "端口必须是数字");
            return false;
        }
    }
    
    /**
     * 设置验证图标
     */
    private void setValidationIcon(JLabel label, boolean valid, String tooltip) {
        if (valid) {
            label.setText("✓");
            label.setForeground(new Color(39, 174, 96));
        } else {
            label.setText("✗");
            label.setForeground(new Color(231, 76, 60));
        }
        label.setToolTipText(tooltip);
    }
    
    /**
     * 获取完整的服务器URL
     */
    private String getServerUrl() {
        String ip = serverIpField.getText().trim();
        String port = serverPortField.getText().trim();
        return "http://" + ip + ":" + port;
    }
    
    /**
     * 从URL解析IP和端口
     */
    private void parseUrlToFields(String url) {
        try {
            // 移除协议前缀
            String address = url.replace("http://", "").replace("https://", "");
            
            // 分离IP和端口
            int colonIndex = address.lastIndexOf(':');
            if (colonIndex > 0) {
                serverIpField.setText(address.substring(0, colonIndex));
                serverPortField.setText(address.substring(colonIndex + 1));
            } else {
                serverIpField.setText(address);
                serverPortField.setText("8775");
            }
        } catch (Exception e) {
            serverIpField.setText("localhost");
            serverPortField.setText("8775");
        }
    }
    
    /**
     * 加载配置
     */
    private void loadConfiguration() {
        // 首先尝试从本地文件加载
        Properties props = loadFromFile();
        
        if (props != null && !props.isEmpty()) {
            serverIpField.setText(props.getProperty(KEY_SERVER_IP, "localhost"));
            serverPortField.setText(props.getProperty(KEY_SERVER_PORT, "8775"));
            
            try {
                int maxHistory = Integer.parseInt(props.getProperty(KEY_MAX_HISTORY, "20"));
                maxHistorySpinner.setValue(Math.max(ConfigManager.MIN_HISTORY_SIZE, 
                    Math.min(ConfigManager.MAX_HISTORY_SIZE, maxHistory)));
            } catch (NumberFormatException e) {
                maxHistorySpinner.setValue(20);
            }
            
            boolean persist = Boolean.parseBoolean(props.getProperty(KEY_PERSIST_CONFIG, "true"));
            persistConfigCheckBox.setSelected(persist);
            
            appendLog("[+] 已从本地配置文件加载配置");
        } else {
            // 从ConfigManager加载
            parseUrlToFields(configManager.getBackendUrl());
            maxHistorySpinner.setValue(configManager.getMaxHistorySize());
            persistConfigCheckBox.setSelected(true);
        }
        
        // 验证字段
        validateIpField();
        validatePortField();
    }
    
    /**
     * 从文件加载配置
     */
    private Properties loadFromFile() {
        File configFile = getConfigFile();
        if (!configFile.exists()) {
            return null;
        }
        
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configFile);
             InputStreamReader reader = new InputStreamReader(fis, "UTF-8")) {
            props.load(reader);
            return props;
        } catch (IOException e) {
            appendLog("[-] 读取配置文件失败: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 保存配置到文件
     */
    private void saveToFile() {
        if (!persistConfigCheckBox.isSelected()) {
            return;
        }
        
        Properties props = new Properties();
        props.setProperty(KEY_SERVER_IP, serverIpField.getText().trim());
        props.setProperty(KEY_SERVER_PORT, serverPortField.getText().trim());
        props.setProperty(KEY_MAX_HISTORY, String.valueOf(maxHistorySpinner.getValue()));
        props.setProperty(KEY_PERSIST_CONFIG, String.valueOf(persistConfigCheckBox.isSelected()));
        
        File configFile = getConfigFile();
        try (FileOutputStream fos = new FileOutputStream(configFile);
             OutputStreamWriter writer = new OutputStreamWriter(fos, "UTF-8")) {
            props.store(writer, "SQLMap WebUI Burp Extension Configuration");
            appendLog("[+] 配置已保存到: " + configFile.getAbsolutePath());
        } catch (IOException e) {
            appendLog("[-] 保存配置文件失败: " + e.getMessage());
            HtmlMessageDialog.showError(this, "错误", "保存配置文件失败: " + e.getMessage());
        }
    }
    
    /**
     * 获取配置文件路径
     */
    private File getConfigFile() {
        // 获取当前工作目录（Burp Suite运行目录）
        String userDir = System.getProperty("user.dir");
        return new File(userDir, CONFIG_FILE_NAME);
    }
    
    /**
     * 重置为默认配置
     */
    private void resetToDefault() {
        serverIpField.setText("localhost");
        serverPortField.setText("8775");
        maxHistorySpinner.setValue(20);
        persistConfigCheckBox.setSelected(true);
        
        validateIpField();
        validatePortField();
        
        appendLog("[+] 已重置为默认配置");
    }
    
    /**
     * 创建临时目录配置面板
     */
    private JPanel createTempDirConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("HTTP请求临时文件目录配置"));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        
        // 第一行: 说明文字
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 4;
        JLabel descLabel = new JLabel("设置SQLMap扫描时保存HTTP原始报文的临时文件目录(后端服务器上的路径)");
        descLabel.setForeground(Color.GRAY);
        panel.add(descLabel, gbc);
        
        // 第二行: 临时目录输入框
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("临时目录:"), gbc);
        
        gbc.gridx = 1; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JPanel inputPanel = new JPanel(new BorderLayout(5, 0));
        tempDirField = new JTextField(30);
        tempDirField.setToolTipText("输入后端服务器上的临时目录路径，留空则使用默认值");
        inputPanel.add(tempDirField, BorderLayout.CENTER);
        
        tempDirStatusLabel = new JLabel();
        tempDirStatusLabel.setPreferredSize(new Dimension(20, 20));
        inputPanel.add(tempDirStatusLabel, BorderLayout.EAST);
        panel.add(inputPanel, gbc);
        
        // 第三行: 按钮
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        
        JButton loadBtn = new JButton("加载当前配置");
        loadBtn.addActionListener(e -> loadTempDirConfig());
        buttonPanel.add(loadBtn);
        
        tempDirSaveBtn = new JButton("保存设置");
        tempDirSaveBtn.addActionListener(e -> saveTempDirConfig());
        buttonPanel.add(tempDirSaveBtn);
        
        tempDirResetBtn = new JButton("恢复默认");
        tempDirResetBtn.addActionListener(e -> resetTempDirConfig());
        buttonPanel.add(tempDirResetBtn);
        
        panel.add(buttonPanel, gbc);
        
        return panel;
    }
    
    /**
     * 加载临时目录配置
     */
    private void loadTempDirConfig() {
        if (!configManager.isConnected()) {
            HtmlMessageDialog.showWarning(this, "未连接", "请先连接后端服务器");
            return;
        }
        
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return apiClient.getTempDirConfig();
            }
            
            @Override
            protected void done() {
                try {
                    String response = get();
                    parseTempDirResponse(response, true);
                } catch (Exception e) {
                    String errorMsg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    appendLog("[-] 加载临时目录配置失败: " + errorMsg);
                    setTempDirStatus(false, "加载失败");
                }
            }
        }.execute();
    }
    
    /**
     * 保存临时目录配置
     */
    private void saveTempDirConfig() {
        if (!configManager.isConnected()) {
            HtmlMessageDialog.showWarning(this, "未连接", "请先连接后端服务器");
            return;
        }
        
        String tempDir = tempDirField.getText().trim();
        
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return apiClient.setTempDirConfig(tempDir.isEmpty() ? null : tempDir);
            }
            
            @Override
            protected void done() {
                try {
                    String response = get();
                    parseTempDirResponse(response, false);
                    appendLog("[+] 临时目录配置已保存");
                    HtmlMessageDialog.showInfo(ServerConfigPanel.this, "保存成功", 
                        "<p>临时目录配置已保存到后端服务器</p>");
                } catch (Exception e) {
                    String errorMsg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    appendLog("[-] 保存临时目录配置失败: " + errorMsg);
                    HtmlMessageDialog.showError(ServerConfigPanel.this, "保存失败", 
                        "<p>无法保存临时目录配置: " + errorMsg + "</p>");
                }
            }
        }.execute();
    }
    
    /**
     * 重置临时目录为默认值
     */
    private void resetTempDirConfig() {
        if (!configManager.isConnected()) {
            HtmlMessageDialog.showWarning(this, "未连接", "请先连接后端服务器");
            return;
        }
        
        int result = JOptionPane.showConfirmDialog(this, 
            "确定要将临时目录恢复为默认值吗？", 
            "确认重置", 
            JOptionPane.YES_NO_OPTION);
        
        if (result != JOptionPane.YES_OPTION) {
            return;
        }
        
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return apiClient.resetTempDirConfig();
            }
            
            @Override
            protected void done() {
                try {
                    String response = get();
                    parseTempDirResponse(response, false);
                    appendLog("[+] 临时目录已恢复为默认值");
                    HtmlMessageDialog.showInfo(ServerConfigPanel.this, "重置成功", 
                        "<p>临时目录已恢复为默认值</p>");
                } catch (Exception e) {
                    String errorMsg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    appendLog("[-] 重置临时目录失败: " + errorMsg);
                    HtmlMessageDialog.showError(ServerConfigPanel.this, "重置失败", 
                        "<p>无法重置临时目录: " + errorMsg + "</p>");
                }
            }
        }.execute();
    }
    
    /**
     * 解析临时目录配置API响应
     */
    private void parseTempDirResponse(String response, boolean showSuccess) {
        try {
            com.google.gson.JsonObject json = com.google.gson.JsonParser.parseString(response).getAsJsonObject();
            if (json.has("success") && json.get("success").getAsBoolean()) {
                com.google.gson.JsonObject data = json.getAsJsonObject("data");
                String currentDir = data.get("currentTempDir").getAsString();
                @SuppressWarnings("unused")
                String defaultDir = data.get("defaultTempDir").getAsString();
                boolean isCustom = data.get("isCustom").getAsBoolean();
                
                tempDirField.setText(currentDir);
                setTempDirStatus(true, isCustom ? "自定义目录" : "默认目录");
                
                if (showSuccess) {
                    appendLog("[+] 临时目录配置: " + currentDir + (isCustom ? " (自定义)" : " (默认)"));
                }
            } else {
                String msg = json.has("msg") ? json.get("msg").getAsString() : "未知错误";
                appendLog("[-] 临时目录配置失败: " + msg);
                setTempDirStatus(false, msg);
            }
        } catch (Exception e) {
            appendLog("[-] 解析临时目录配置响应失败: " + e.getMessage());
            setTempDirStatus(false, "解析失败");
        }
    }
    
    /**
     * 设置临时目录状态图标
     */
    private void setTempDirStatus(boolean success, String tooltip) {
        if (success) {
            tempDirStatusLabel.setText("✓");
            tempDirStatusLabel.setForeground(new Color(39, 174, 96));
        } else {
            tempDirStatusLabel.setText("✗");
            tempDirStatusLabel.setForeground(new Color(231, 76, 60));
        }
        tempDirStatusLabel.setToolTipText(tooltip);
    }
    
    private void testConnection() {
        // 先验证输入
        if (!validateIpField() || !validatePortField()) {
            HtmlMessageDialog.showWarning(this, "验证失败", "请先修正配置错误后再测试连接");
            return;
        }
        
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                String url = getServerUrl();
                apiClient.setBaseUrl(url);
                return apiClient.getVersion();
            }
            
            @Override
            protected void done() {
                try {
                    String version = get();
                    
                    configManager.setConnected(true);
                    if (onConnectionStatusChange != null) {
                        onConnectionStatusChange.accept(true);
                    }
                    
                    appendLog("[+] 连接成功! 后端版本: " + version);
                    
                    HtmlMessageDialog.showInfo(ServerConfigPanel.this, "连接成功",
                        "<h3 style='color: green;'>✓ 连接成功!</h3>" +
                        "<p><b>后端版本:</b> " + version + "</p>" +
                        "<p><b>服务器地址:</b> " + getServerUrl() + "</p>" +
                        "<hr>" +
                        "<p>现在可以使用右键菜单发送扫描任务了。</p>");
                        
                } catch (Exception e) {
                    configManager.setConnected(false);
                    if (onConnectionStatusChange != null) {
                        onConnectionStatusChange.accept(false);
                    }
                    
                    String errorMsg = e.getMessage();
                    if (e.getCause() != null) {
                        errorMsg = e.getCause().getMessage();
                    }
                    
                    appendLog("[-] 连接失败: " + errorMsg);
                    
                    HtmlMessageDialog.showError(ServerConfigPanel.this, "连接失败",
                        "<h3 style='color: red;'>✗ 连接失败</h3>" +
                        "<p><b>服务器地址:</b> " + getServerUrl() + "</p>" +
                        "<p><b>错误信息:</b> " + errorMsg + "</p>" +
                        "<hr>" +
                        "<p>请检查:</p>" +
                        "<ul>" +
                        "<li>后端服务是否已启动</li>" +
                        "<li>IP地址和端口是否正确</li>" +
                        "<li>防火墙是否阻止连接</li>" +
                        "</ul>");
                }
            }
        }.execute();
    }
    
    private void saveServerConfig() {
        // 先验证输入
        if (!validateIpField() || !validatePortField()) {
            HtmlMessageDialog.showWarning(this, "验证失败", "请先修正配置错误后再保存");
            return;
        }
        
        String url = getServerUrl();
        configManager.setBackendUrl(url);
        if (onBackendUrlChange != null) {
            onBackendUrlChange.accept(url);
        }
        
        int maxHistory = (Integer) maxHistorySpinner.getValue();
        configManager.setMaxHistorySize(maxHistory);
        
        // 保存到本地文件
        saveToFile();
        
        if (onConnectionStatusChange != null) {
            onConnectionStatusChange.accept(false);
        }
        
        appendLog("[+] 服务器配置已保存. URL: " + url + ", 历史记录最大数量: " + maxHistory);
        
        HtmlMessageDialog.showInfo(this, "保存成功",
            "<h3 style='color: green;'>✓ 配置已保存</h3>" +
            "<p><b>服务器:</b> " + url + "</p>" +
            "<p><b>历史记录上限:</b> " + maxHistory + " 条</p>" +
            (persistConfigCheckBox.isSelected() ? 
                "<p><b>持久化:</b> 已保存到本地文件</p>" : 
                "<p><b>持久化:</b> 未启用</p>") +
            "<hr>" +
            "<p>请点击「测试连接」验证后端可用性。</p>");
    }
}
