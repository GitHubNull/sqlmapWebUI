package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.ConfigManager.TerminalType;
import com.sqlmapwebui.burp.SqlmapApiClient;
import com.sqlmapwebui.burp.util.CommandExecutor;
import com.sqlmapwebui.burp.util.CommandExecutor.ExecutionResult;
import com.sqlmapwebui.burp.util.SqlCommandBuilder;
import com.sqlmapwebui.burp.util.SqlCommandBuilder.OsType;
import com.sqlmapwebui.burp.util.SqlCommandBuilder.TerminalOption;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.function.Consumer;

/**
 * 直接执行功能配置面板
 * 管理右键菜单"执行SQLMap扫描"功能的配置
 */
public class DirectExecuteConfigPanel extends BaseConfigPanel {

    private JTextField pythonPathField;
    private JTextField sqlmapPathField;
    private JComboBox<TerminalOption> terminalComboBox;
    private JCheckBox keepTerminalCheckBox;

    private JButton pythonBrowseBtn;
    private JButton sqlmapBrowseBtn;
    private JButton pythonTestBtn;
    private JButton sqlmapTestBtn;

    private JLabel pythonStatusLabel;
    private JLabel sqlmapStatusLabel;
    private JLabel terminalStatusLabel;
    
    // 标题规则面板
    private TitleRulesPanel titleRulesPanel;

    public DirectExecuteConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient, Consumer<String> logAppender) {
        super(configManager, apiClient, logAppender);
    }

    @Override
    protected void initializePanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));

        // 配置表单
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("直接执行功能配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // 功能说明
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JTextArea descArea = new JTextArea(
            "此功能允许您直接在终端中执行SQLMap扫描，" +
            "无需通过后端服务器。请配置Python和SQLMap路径。");
        descArea.setEditable(false);
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setOpaque(false);
        descArea.setForeground(Color.GRAY);
        descArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        descArea.setBorder(BorderFactory.createEmptyBorder());
        formPanel.add(descArea, gbc);
        row++;

        // 分隔线
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(new JSeparator(), gbc);
        row++;

        // Python路径配置
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Python路径:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JPanel pythonPanel = new JPanel(new BorderLayout(5, 0));
        pythonPathField = new JTextField(30);
        pythonPathField.setToolTipText("Python解释器路径，留空则使用系统PATH中的python");
        pythonPanel.add(pythonPathField, BorderLayout.CENTER);

        JPanel pythonBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        pythonBrowseBtn = new JButton("浏览...");
        pythonBrowseBtn.addActionListener(e -> browsePythonPath());
        pythonBtnPanel.add(pythonBrowseBtn);

        pythonTestBtn = new JButton("测试");
        pythonTestBtn.addActionListener(e -> testPythonPath());
        pythonBtnPanel.add(pythonTestBtn);

        pythonPanel.add(pythonBtnPanel, BorderLayout.EAST);
        formPanel.add(pythonPanel, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        pythonStatusLabel = new JLabel();
        pythonStatusLabel.setPreferredSize(new Dimension(20, 20));
        formPanel.add(pythonStatusLabel, gbc);

        gbc.gridx = 3;
        JLabel pythonHint = new JLabel("(可选，留空使用系统默认)");
        pythonHint.setForeground(Color.GRAY);
        formPanel.add(pythonHint, gbc);
        row++;

        // SQLMap路径配置
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("SQLMap路径:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JPanel sqlmapPanel = new JPanel(new BorderLayout(5, 0));
        sqlmapPathField = new JTextField(30);
        sqlmapPathField.setToolTipText("SQLMap脚本路径 (sqlmap.py)");
        sqlmapPanel.add(sqlmapPathField, BorderLayout.CENTER);

        JPanel sqlmapBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        sqlmapBrowseBtn = new JButton("浏览...");
        sqlmapBrowseBtn.addActionListener(e -> browseSqlmapPath());
        sqlmapBtnPanel.add(sqlmapBrowseBtn);

        sqlmapTestBtn = new JButton("测试");
        sqlmapTestBtn.addActionListener(e -> testSqlmapPath());
        sqlmapBtnPanel.add(sqlmapTestBtn);

        sqlmapPanel.add(sqlmapBtnPanel, BorderLayout.EAST);
        formPanel.add(sqlmapPanel, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        sqlmapStatusLabel = new JLabel();
        sqlmapStatusLabel.setPreferredSize(new Dimension(20, 20));
        formPanel.add(sqlmapStatusLabel, gbc);

        gbc.gridx = 3;
        JLabel sqlmapHint = new JLabel("(必填，sqlmap.py路径)");
        sqlmapHint.setForeground(new Color(231, 76, 60));
        formPanel.add(sqlmapHint, gbc);
        row++;

        // 终端类型配置
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("终端类型:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        List<TerminalOption> terminalOptions = SqlCommandBuilder.getTerminalOptions();
        terminalComboBox = new JComboBox<>(terminalOptions.toArray(new TerminalOption[0]));
        terminalComboBox.setToolTipText("选择执行SQLMap命令的终端");
        formPanel.add(terminalComboBox, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        terminalStatusLabel = new JLabel();
        terminalStatusLabel.setPreferredSize(new Dimension(20, 20));
        formPanel.add(terminalStatusLabel, gbc);
        row++;

        // 保持终端打开选项
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.NONE;
        JPanel keepPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        keepTerminalCheckBox = new JCheckBox("执行后保持终端打开", true);
        keepTerminalCheckBox.setToolTipText("勾选后，SQLMap执行完毕后终端窗口不会自动关闭");
        keepPanel.add(keepTerminalCheckBox);
        formPanel.add(keepPanel, gbc);
        row++;

        // 当前系统信息
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        OsType osType = SqlCommandBuilder.detectOs();
        String osInfo = String.format("当前操作系统: %s", getOsDisplayName(osType));
        JLabel osLabel = new JLabel(osInfo);
        osLabel.setForeground(new Color(52, 152, 219));
        formPanel.add(osLabel, gbc);
        row++;
        
        // 分隔线
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(new JSeparator(), gbc);
        row++;
        
        // 标题配置区域
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JPanel titlePanel = createTitleConfigPanel();
        formPanel.add(titlePanel, gbc);
        row++;

        // 按钮面板
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));

        JButton saveButton = new JButton("保存设置");
        saveButton.addActionListener(e -> saveConfiguration());
        buttonPanel.add(saveButton);

        JButton resetButton = new JButton("恢复默认");
        resetButton.addActionListener(e -> resetToDefault());
        buttonPanel.add(resetButton);

        formPanel.add(buttonPanel, gbc);

        mainPanel.add(formPanel, BorderLayout.NORTH);

        // 帮助面板
        JPanel helpPanel = createHelpPanel();
        mainPanel.add(helpPanel, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);

        // 加载配置
        loadConfiguration();
    }

    /**
     * 获取操作系统显示名称
     */
    private String getOsDisplayName(OsType osType) {
        switch (osType) {
            case WINDOWS: return "Windows";
            case MACOS: return "macOS";
            case LINUX: return "Linux";
            default: return "未知";
        }
    }
    
    /**
     * 创建标题配置面板
     */
    private JPanel createTitleConfigPanel() {
        JPanel wrapperPanel = new JPanel(new BorderLayout());
        wrapperPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "终端窗口标题规则配置",
            TitledBorder.LEFT,
            TitledBorder.TOP
        ));
        
        // 使用新的 TitleRulesPanel
        titleRulesPanel = new TitleRulesPanel(configManager);
        wrapperPanel.add(titleRulesPanel, BorderLayout.CENTER);
        
        return wrapperPanel;
    }

    /**
     * 创建帮助面板
     */
    private JPanel createHelpPanel() {
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
        helpScrollPane.setPreferredSize(new Dimension(600, 250));
        helpPanel.add(helpScrollPane, BorderLayout.CENTER);

        return helpPanel;
    }

    /**
     * 创建帮助内容
     */
    private String createHelpContent() {
        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 5px; }" +
            "h3 { color: #2c3e50; margin: 10px 0 5px 0; border-bottom: 1px solid #bdc3c7; padding-bottom: 3px; }" +
            "h4 { color: #34495e; margin: 8px 0 3px 0; }" +
            "ul { margin: 3px 0 8px 20px; padding: 0; }" +
            "li { margin: 2px 0; }" +
            ".code { font-family: 'Consolas', monospace; background: #ecf0f1; padding: 1px 4px; border-radius: 3px; }" +
            ".warning { background: #fff3cd; padding: 5px; border-left: 3px solid #ffc107; margin: 5px 0; }" +
            ".success { color: #27ae60; }" +
            "</style></head><body>" +

            "<h3>功能说明</h3>" +
            "<ul>" +
            "<li>在Burp的HTTP请求上<strong>右键</strong>，选择 <span class='code'>执行SQLMap扫描</span></li>" +
            "<li>系统会自动打开终端窗口并执行SQLMap命令</li>" +
            "<li>HTTP请求会保存为临时文件，使用 <span class='code'>-r</span> 参数传递</li>" +
            "</ul>" +

            "<h3>配置说明</h3>" +
            "<h4>Python路径</h4>" +
            "<ul>" +
            "<li>可选配置，留空使用系统PATH中的Python</li>" +
            "<li>Windows: 如 <span class='code'>C:\\Python39\\python.exe</span></li>" +
            "<li>Linux/macOS: 如 <span class='code'>/usr/bin/python3</span></li>" +
            "</ul>" +

            "<h4>SQLMap路径</h4>" +
            "<ul>" +
            "<li><b>必填</b>：指定sqlmap.py脚本的完整路径</li>" +
            "<li>如 <span class='code'>C:\\sqlmap\\sqlmap.py</span> 或 <span class='code'>/opt/sqlmap/sqlmap.py</span></li>" +
            "</ul>" +

            "<h4>终端类型</h4>" +
            "<ul>" +
            "<li><span class='code'>自动检测</span>：根据操作系统自动选择终端</li>" +
            "<li>Windows: CMD 或 PowerShell</li>" +
            "<li>Linux: GNOME Terminal 或 XTerm</li>" +
            "<li>macOS: Terminal.app 或 iTerm2</li>" +
            "</ul>" +

            "<h4>标题规则</h4>" +
            "<ul>" +
            "<li>按优先级顺序匹配规则，数字越小优先级越高</li>" +
            "<li>默认规则 (URL路径) 不可删除，作为最终兜底</li>" +
            "<li>首个成功匹配的规则将被用于终端标题</li>" +
            "<li>支持从 Host、URL路径、请求方法、Content-Type、自定义正则等提取标题</li>" +
            "</ul>" +

            "<h4>配置导入导出</h4>" +
            "<ul>" +
            "<li>在「常用配置」标签页可使用导入导出功能</li>" +
            "<li>支持导出所有配置到 JSON 文件进行备份</li>" +
            "<li>支持从 JSON 文件导入配置，方便团队共享</li>" +
            "</ul>" +

            "<div class='warning'>" +
            "<b>注意：</b>" +
            "<ul>" +
            "<li>确保已安装Python并配置正确</li>" +
            "<li>确保SQLMap已下载到本地</li>" +
            "<li>临时文件在执行后会保留，可手动删除</li>" +
            "<li>命令执行功能不经过后端服务器，直接在本地终端运行</li>" +
            "</ul>" +
            "</div>" +

            "<h3>测试功能</h3>" +
            "<p>点击「测试」按钮验证配置是否正确：</p>" +
            "<ul>" +
            "<li>Python测试：检查Python是否可用并显示版本</li>" +
            "<li>SQLMap测试：检查SQLMap脚本是否有效</li>" +
            "</ul>" +

            "<h3>右键菜单选项</h3>" +
            "<ul>" +
            "<li><b>Send to SQLMap WebUI</b>: 使用默认配置发送到后端服务器</li>" +
            "<li><b>Send to SQLMap WebUI (选择配置)</b>: 选择特定配置后发送到后端</li>" +
            "<li><b>执行SQLMap扫描</b>: 使用命令执行配置直接在终端运行</li>" +
            "</ul>" +

            "</body></html>";
    }

    /**
     * 浏览Python路径
     */
    private void browsePythonPath() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择Python解释器");

        // 根据操作系统设置文件过滤器
        OsType osType = SqlCommandBuilder.detectOs();
        if (osType == OsType.WINDOWS) {
            chooser.setFileFilter(new FileNameExtensionFilter("可执行文件 (*.exe)", "exe"));
        } else {
            chooser.setFileFilter(null);
        }

        String currentPath = pythonPathField.getText().trim();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            if (currentFile.exists()) {
                chooser.setCurrentDirectory(currentFile.getParentFile());
                chooser.setSelectedFile(currentFile);
            }
        } else {
            chooser.setCurrentDirectory(FileSystemView.getFileSystemView().getHomeDirectory());
        }

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            pythonPathField.setText(chooser.getSelectedFile().getAbsolutePath());
            setLabelStatus(pythonStatusLabel, null, null);
        }
    }

    /**
     * 浏览SQLMap路径
     */
    private void browseSqlmapPath() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择SQLMap脚本 (sqlmap.py)");
        chooser.setFileFilter(new FileNameExtensionFilter("Python脚本 (*.py)", "py"));

        String currentPath = sqlmapPathField.getText().trim();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            if (currentFile.exists()) {
                chooser.setCurrentDirectory(currentFile.getParentFile());
                chooser.setSelectedFile(currentFile);
            }
        } else {
            chooser.setCurrentDirectory(FileSystemView.getFileSystemView().getHomeDirectory());
        }

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            sqlmapPathField.setText(chooser.getSelectedFile().getAbsolutePath());
            setLabelStatus(sqlmapStatusLabel, null, null);
        }
    }

    /**
     * 测试Python路径
     */
    private void testPythonPath() {
        pythonTestBtn.setEnabled(false);
        setLabelStatus(pythonStatusLabel, null, "测试中...");

        SwingWorker<ExecutionResult, Void> worker = new SwingWorker<>() {
            @Override
            protected ExecutionResult doInBackground() {
                return CommandExecutor.validatePythonPath(pythonPathField.getText().trim());
            }

            @Override
            protected void done() {
                try {
                    ExecutionResult result = get();
                    if (result.isSuccess()) {
                        String version = result.getMessage();
                        setLabelStatus(pythonStatusLabel, true, version);
                        appendLog("[+] Python测试成功: " + version);
                        JOptionPane.showMessageDialog(DirectExecuteConfigPanel.this,
                            "Python测试成功!\n版本: " + version,
                            "测试成功", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        setLabelStatus(pythonStatusLabel, false, result.getMessage());
                        appendLog("[-] Python测试失败: " + result.getMessage());
                        JOptionPane.showMessageDialog(DirectExecuteConfigPanel.this,
                            "Python测试失败:\n" + result.getMessage(),
                            "测试失败", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    setLabelStatus(pythonStatusLabel, false, e.getMessage());
                    appendLog("[-] Python测试异常: " + e.getMessage());
                } finally {
                    pythonTestBtn.setEnabled(true);
                }
            }
        };
        worker.execute();
    }

    /**
     * 测试SQLMap路径
     */
    private void testSqlmapPath() {
        String sqlmapPath = sqlmapPathField.getText().trim();
        if (sqlmapPath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "请先输入SQLMap路径", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }

        sqlmapTestBtn.setEnabled(false);
        setLabelStatus(sqlmapStatusLabel, null, "测试中...");

        SwingWorker<ExecutionResult, Void> worker = new SwingWorker<>() {
            @Override
            protected ExecutionResult doInBackground() {
                return CommandExecutor.validateSqlmapPath(pythonPathField.getText().trim(), sqlmapPath);
            }

            @Override
            protected void done() {
                try {
                    ExecutionResult result = get();
                    if (result.isSuccess()) {
                        String version = result.getMessage();
                        setLabelStatus(sqlmapStatusLabel, true, version);
                        appendLog("[+] SQLMap测试成功: " + version);
                        JOptionPane.showMessageDialog(DirectExecuteConfigPanel.this,
                            "SQLMap测试成功!\n版本: " + version,
                            "测试成功", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        setLabelStatus(sqlmapStatusLabel, false, result.getMessage());
                        appendLog("[-] SQLMap测试失败: " + result.getMessage());
                        JOptionPane.showMessageDialog(DirectExecuteConfigPanel.this,
                            "SQLMap测试失败:\n" + result.getMessage(),
                            "测试失败", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    setLabelStatus(sqlmapStatusLabel, false, e.getMessage());
                    appendLog("[-] SQLMap测试异常: " + e.getMessage());
                } finally {
                    sqlmapTestBtn.setEnabled(true);
                }
            }
        };
        worker.execute();
    }

    /**
     * 加载配置
     */
    private void loadConfiguration() {
        pythonPathField.setText(configManager.getDirectPythonPath());
        sqlmapPathField.setText(configManager.getDirectSqlmapPath());
        keepTerminalCheckBox.setSelected(configManager.isDirectKeepTerminal());

        // 选择终端类型
        TerminalType savedType = configManager.getDirectTerminalType();
        List<TerminalOption> options = SqlCommandBuilder.getTerminalOptions();
        for (int i = 0; i < options.size(); i++) {
            if (options.get(i).getType() == savedType) {
                terminalComboBox.setSelectedIndex(i);
                break;
            }
        }

        // 标题规则面板会在自己的构造函数中加载配置

        setLabelStatus(terminalStatusLabel, true, "配置已加载");
    }

    /**
     * 保存配置
     */
    private void saveConfiguration() {
        String pythonPath = pythonPathField.getText().trim();
        String sqlmapPath = sqlmapPathField.getText().trim();
        TerminalOption selectedOption = (TerminalOption) terminalComboBox.getSelectedItem();
        boolean keepTerminal = keepTerminalCheckBox.isSelected();

        // 验证SQLMap路径（必填）
        if (sqlmapPath.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "SQLMap路径为必填项，请配置sqlmap.py的路径",
                "配置不完整", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 验证SQLMap文件是否存在
        File sqlmapFile = new File(sqlmapPath);
        if (!sqlmapFile.exists()) {
            int result = JOptionPane.showConfirmDialog(this,
                "SQLMap文件不存在: " + sqlmapPath + "\n是否仍要保存配置？",
                "文件不存在", JOptionPane.YES_NO_OPTION);
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }

        configManager.setDirectPythonPath(pythonPath);
        configManager.setDirectSqlmapPath(sqlmapPath);
        if (selectedOption != null) {
            configManager.setDirectTerminalType(selectedOption.getType());
        }
        configManager.setDirectKeepTerminal(keepTerminal);
        
        // 保存标题规则配置（由 TitleRulesPanel 内部处理）
        if (titleRulesPanel != null) {
            titleRulesPanel.saveConfiguration();
        }

        appendLog("[+] 直接执行配置已保存");
        appendLog("    Python路径: " + (pythonPath.isEmpty() ? "(系统默认)" : pythonPath));
        appendLog("    SQLMap路径: " + sqlmapPath);
        appendLog("    终端类型: " + (selectedOption != null ? selectedOption.getDisplayName() : "自动"));
        appendLog("    保持终端: " + (keepTerminal ? "是" : "否"));
        appendLog("    标题规则: 已保存");

        setLabelStatus(terminalStatusLabel, true, "已保存");

        HtmlMessageDialog.showInfo(this, "保存成功",
            "<h3 style='color: green;'>配置已保存</h3>" +
            "<p><b>Python路径:</b> " + (pythonPath.isEmpty() ? "系统默认" : pythonPath) + "</p>" +
            "<p><b>SQLMap路径:</b> " + sqlmapPath + "</p>" +
            "<p><b>终端类型:</b> " + (selectedOption != null ? selectedOption.getDisplayName() : "自动") + "</p>" +
            "<p><b>保持终端:</b> " + (keepTerminal ? "是" : "否") + "</p>" +
            "<p><b>标题规则:</b> 已保存</p>");
    }

    /**
     * 恢复默认设置
     */
    private void resetToDefault() {
        int result = JOptionPane.showConfirmDialog(this,
            "确定要恢复默认设置吗？",
            "确认重置", JOptionPane.YES_NO_OPTION);

        if (result != JOptionPane.YES_OPTION) {
            return;
        }

        pythonPathField.setText("");
        sqlmapPathField.setText("");
        terminalComboBox.setSelectedIndex(0); // 自动检测
        keepTerminalCheckBox.setSelected(true);

        // 重置标题规则配置为默认值
        if (titleRulesPanel != null) {
            titleRulesPanel.resetToDefault();
        }

        setLabelStatus(pythonStatusLabel, null, null);
        setLabelStatus(sqlmapStatusLabel, null, null);
        setLabelStatus(terminalStatusLabel, true, "已恢复默认");

        appendLog("[+] 直接执行配置已恢复为默认值");
    }

    /**
     * 设置标签状态
     */
    private void setLabelStatus(JLabel label, Boolean success, String text) {
        if (success == null) {
            label.setText(text != null ? text : "");
            label.setForeground(Color.GRAY);
        } else if (success) {
            label.setText("✓");
            label.setForeground(new Color(39, 174, 96));
            label.setToolTipText(text);
        } else {
            label.setText("✗");
            label.setForeground(new Color(231, 76, 60));
            label.setToolTipText(text);
        }
    }
}
