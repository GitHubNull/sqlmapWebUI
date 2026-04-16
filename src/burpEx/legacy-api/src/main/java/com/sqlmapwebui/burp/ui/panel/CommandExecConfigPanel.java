package com.sqlmapwebui.burp.ui.panel;
import com.sqlmapwebui.burp.ui.dialog.CommandExecHelpDialog;

import com.sqlmapwebui.burp.ui.dialog.HtmlMessageDialog;


import com.sqlmapwebui.burp.config.CommandExecConfig;
import com.sqlmapwebui.burp.config.ConfigManager;
import com.sqlmapwebui.burp.config.ConfigManager.TerminalType;
import com.sqlmapwebui.burp.config.PresetConfigDatabase;
import com.sqlmapwebui.burp.api.SqlmapApiClient;
import com.sqlmapwebui.burp.util.CommandExecutor;
import com.sqlmapwebui.burp.util.CommandExecutor.ExecutionResult;
import com.sqlmapwebui.burp.util.SqlCommandBuilder;
import com.sqlmapwebui.burp.util.SqlCommandBuilder.OsType;
import com.sqlmapwebui.burp.util.SqlCommandBuilder.TerminalOption;
import com.sqlmapwebui.burp.model.TitleRule;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.function.Consumer;

/**
 * 命令行执行配置面板
 * 合并剪贴板配置和直接执行配置
 */
public class CommandExecConfigPanel extends BaseConfigPanel {

    // 基础配置
    private JCheckBox autoCopyCheckBox;
    private JTextField tempDirField;
    private JButton tempDirBrowseBtn;
    private JLabel tempDirStatusLabel;
    
    // 脚本临时目录配置
    private JTextField scriptTempDirField;
    private JButton scriptTempDirBrowseBtn;
    private JLabel scriptTempDirStatusLabel;

    // 执行环境配置
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

    // 数据库引用
    private PresetConfigDatabase database;

    public CommandExecConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient, Consumer<String> logAppender) {
        super(configManager, apiClient, logAppender);
    }

    @Override
    protected void initializePanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));

        // 配置表单
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 8, 5, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        // ==================== 基础配置区域 ====================
        JPanel basicPanel = new JPanel(new GridBagLayout());
        basicPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "基础配置",
            TitledBorder.LEFT,
            TitledBorder.TOP
        ));

        GridBagConstraints gbcBasic = new GridBagConstraints();
        gbcBasic.insets = new Insets(5, 8, 5, 8);
        gbcBasic.anchor = GridBagConstraints.WEST;

        // 自动复制选项
        gbcBasic.gridx = 0; gbcBasic.gridy = 0; gbcBasic.gridwidth = 3;
        autoCopyCheckBox = new JCheckBox("自动复制命令到剪贴板", true);
        autoCopyCheckBox.setToolTipText("勾选后，生成命令时会自动复制到剪贴板；取消勾选则会显示预览对话框");
        basicPanel.add(autoCopyCheckBox, gbcBasic);

        // 临时文件目录配置
        gbcBasic.gridx = 0; gbcBasic.gridy = 1; gbcBasic.gridwidth = 1;
        gbcBasic.fill = GridBagConstraints.NONE; gbcBasic.weightx = 0;
        basicPanel.add(new JLabel("临时目录:"), gbcBasic);

        gbcBasic.gridx = 1; gbcBasic.fill = GridBagConstraints.HORIZONTAL; gbcBasic.weightx = 1.0;
        JPanel tempDirPanel = new JPanel(new BorderLayout(5, 0));
        tempDirField = new JTextField(30);
        tempDirField.setToolTipText("设置保存HTTP请求文件的目录，留空则使用系统默认临时目录");
        tempDirPanel.add(tempDirField, BorderLayout.CENTER);

        tempDirBrowseBtn = new JButton("浏览...");
        tempDirBrowseBtn.addActionListener(e -> browseTempDir());
        tempDirPanel.add(tempDirBrowseBtn, BorderLayout.EAST);

        basicPanel.add(tempDirPanel, gbcBasic);

        gbcBasic.gridx = 2; gbcBasic.fill = GridBagConstraints.NONE; gbcBasic.weightx = 0;
        tempDirStatusLabel = new JLabel();
        tempDirStatusLabel.setPreferredSize(new Dimension(20, 20));
        basicPanel.add(tempDirStatusLabel, gbcBasic);

        // 脚本临时目录配置
        gbcBasic.gridx = 0; gbcBasic.gridy = 2; gbcBasic.gridwidth = 1;
        gbcBasic.fill = GridBagConstraints.NONE; gbcBasic.weightx = 0;
        basicPanel.add(new JLabel("脚本目录:"), gbcBasic);

        gbcBasic.gridx = 1; gbcBasic.fill = GridBagConstraints.HORIZONTAL; gbcBasic.weightx = 1.0;
        JPanel scriptTempDirPanel = new JPanel(new BorderLayout(5, 0));
        scriptTempDirField = new JTextField(30);
        scriptTempDirField.setToolTipText("设置临时执行脚本的存储目录（用于设置终端标题），留空则使用临时目录");
        scriptTempDirPanel.add(scriptTempDirField, BorderLayout.CENTER);

        scriptTempDirBrowseBtn = new JButton("浏览...");
        scriptTempDirBrowseBtn.addActionListener(e -> browseScriptTempDir());
        scriptTempDirPanel.add(scriptTempDirBrowseBtn, BorderLayout.EAST);

        basicPanel.add(scriptTempDirPanel, gbcBasic);

        gbcBasic.gridx = 2; gbcBasic.fill = GridBagConstraints.NONE; gbcBasic.weightx = 0;
        scriptTempDirStatusLabel = new JLabel();
        scriptTempDirStatusLabel.setPreferredSize(new Dimension(20, 20));
        basicPanel.add(scriptTempDirStatusLabel, gbcBasic);

        // 添加到主表单
        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(basicPanel, gbc);

        // ==================== 执行环境区域 ====================
        JPanel execPanel = new JPanel(new GridBagLayout());
        execPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "执行环境",
            TitledBorder.LEFT,
            TitledBorder.TOP
        ));

        GridBagConstraints gbcExec = new GridBagConstraints();
        gbcExec.insets = new Insets(5, 8, 5, 8);
        gbcExec.anchor = GridBagConstraints.WEST;
        int execRow = 0;

        // Python路径配置
        gbcExec.gridx = 0; gbcExec.gridy = execRow; gbcExec.gridwidth = 1;
        gbcExec.fill = GridBagConstraints.NONE; gbcExec.weightx = 0;
        execPanel.add(new JLabel("Python路径:"), gbcExec);

        gbcExec.gridx = 1; gbcExec.fill = GridBagConstraints.HORIZONTAL; gbcExec.weightx = 1.0;
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
        execPanel.add(pythonPanel, gbcExec);

        gbcExec.gridx = 2; gbcExec.fill = GridBagConstraints.NONE; gbcExec.weightx = 0;
        pythonStatusLabel = new JLabel();
        pythonStatusLabel.setPreferredSize(new Dimension(20, 20));
        execPanel.add(pythonStatusLabel, gbcExec);

        gbcExec.gridx = 3;
        JLabel pythonHint = new JLabel("(可选)");
        pythonHint.setForeground(Color.GRAY);
        execPanel.add(pythonHint, gbcExec);
        execRow++;

        // SQLMap路径配置
        gbcExec.gridx = 0; gbcExec.gridy = execRow; gbcExec.gridwidth = 1;
        gbcExec.fill = GridBagConstraints.NONE; gbcExec.weightx = 0;
        execPanel.add(new JLabel("SQLMap路径:"), gbcExec);

        gbcExec.gridx = 1; gbcExec.fill = GridBagConstraints.HORIZONTAL; gbcExec.weightx = 1.0;
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
        execPanel.add(sqlmapPanel, gbcExec);

        gbcExec.gridx = 2; gbcExec.fill = GridBagConstraints.NONE; gbcExec.weightx = 0;
        sqlmapStatusLabel = new JLabel();
        sqlmapStatusLabel.setPreferredSize(new Dimension(20, 20));
        execPanel.add(sqlmapStatusLabel, gbcExec);

        gbcExec.gridx = 3;
        JLabel sqlmapHint = new JLabel("(必填)");
        sqlmapHint.setForeground(new Color(231, 76, 60));
        execPanel.add(sqlmapHint, gbcExec);
        execRow++;

        // 终端类型配置
        gbcExec.gridx = 0; gbcExec.gridy = execRow; gbcExec.gridwidth = 1;
        gbcExec.fill = GridBagConstraints.NONE; gbcExec.weightx = 0;
        execPanel.add(new JLabel("终端类型:"), gbcExec);

        gbcExec.gridx = 1; gbcExec.fill = GridBagConstraints.HORIZONTAL; gbcExec.weightx = 1.0;
        List<TerminalOption> terminalOptions = SqlCommandBuilder.getTerminalOptions();
        terminalComboBox = new JComboBox<>(terminalOptions.toArray(new TerminalOption[0]));
        terminalComboBox.setToolTipText("选择执行SQLMap命令的终端");
        execPanel.add(terminalComboBox, gbcExec);

        gbcExec.gridx = 2; gbcExec.fill = GridBagConstraints.NONE; gbcExec.weightx = 0;
        terminalStatusLabel = new JLabel();
        terminalStatusLabel.setPreferredSize(new Dimension(20, 20));
        execPanel.add(terminalStatusLabel, gbcExec);
        execRow++;

        // 保持终端打开选项
        gbcExec.gridx = 0; gbcExec.gridy = execRow; gbcExec.gridwidth = 4;
        gbcExec.fill = GridBagConstraints.NONE;
        JPanel keepPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        keepTerminalCheckBox = new JCheckBox("执行后保持终端打开", true);
        keepTerminalCheckBox.setToolTipText("勾选后，SQLMap执行完毕后终端窗口不会自动关闭");
        keepPanel.add(keepTerminalCheckBox);
        execPanel.add(keepPanel, gbcExec);
        execRow++;

        // 当前系统信息
        gbcExec.gridx = 0; gbcExec.gridy = execRow; gbcExec.gridwidth = 4;
        gbcExec.fill = GridBagConstraints.HORIZONTAL;
        OsType osType = SqlCommandBuilder.detectOs();
        String osInfo = String.format("当前操作系统: %s", getOsDisplayName(osType));
        JLabel osLabel = new JLabel(osInfo);
        osLabel.setForeground(new Color(52, 152, 219));
        execPanel.add(osLabel, gbcExec);

        // 添加到主表单
        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(execPanel, gbc);

        // ==================== 标题规则区域 ====================
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "终端窗口标题规则",
            TitledBorder.LEFT,
            TitledBorder.TOP
        ));

        titleRulesPanel = new TitleRulesPanel(configManager);
        titlePanel.add(titleRulesPanel, BorderLayout.CENTER);

        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(titlePanel, gbc);

        // ==================== 按钮面板 ====================
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 5));

        JButton saveButton = new JButton("保存配置");
        saveButton.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        saveButton.addActionListener(e -> saveConfiguration());
        buttonPanel.add(saveButton);

        JButton resetButton = new JButton("恢复默认");
        resetButton.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        resetButton.addActionListener(e -> resetToDefault());
        buttonPanel.add(resetButton);

        JButton helpButton = new JButton("使用帮助");
        helpButton.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        helpButton.addActionListener(e -> showHelpDialog());
        buttonPanel.add(helpButton);

        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        formPanel.add(buttonPanel, gbc);

        mainPanel.add(formPanel, BorderLayout.NORTH);
        add(mainPanel, BorderLayout.CENTER);

        // 加载配置
        loadConfiguration();
    }

    /**
     * 设置数据库引用
     */
    public void setDatabase(PresetConfigDatabase database) {
        this.database = database;
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
     * 浏览临时目录
     */
    private void browseTempDir() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("选择临时文件目录");

        String currentPath = tempDirField.getText().trim();
        if (!currentPath.isEmpty()) {
            File currentDir = new File(currentPath);
            if (currentDir.exists() && currentDir.isDirectory()) {
                chooser.setCurrentDirectory(currentDir);
                chooser.setSelectedFile(currentDir);
            }
        } else {
            chooser.setCurrentDirectory(FileSystemView.getFileSystemView().getHomeDirectory());
        }

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedDir = chooser.getSelectedFile();
            tempDirField.setText(selectedDir.getAbsolutePath());
            setStatusLabel(tempDirStatusLabel, true, "已选择");
        }
    }

    /**
     * 浏览脚本临时目录
     */
    private void browseScriptTempDir() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("选择脚本临时目录");

        String currentPath = scriptTempDirField.getText().trim();
        if (!currentPath.isEmpty()) {
            File currentDir = new File(currentPath);
            if (currentDir.exists() && currentDir.isDirectory()) {
                chooser.setCurrentDirectory(currentDir);
                chooser.setSelectedFile(currentDir);
            }
        } else {
            // 如果临时目录已设置，则默认使用该目录
            String tempDir = tempDirField.getText().trim();
            if (!tempDir.isEmpty()) {
                File tempDirFile = new File(tempDir);
                if (tempDirFile.exists() && tempDirFile.isDirectory()) {
                    chooser.setCurrentDirectory(tempDirFile);
                }
            } else {
                chooser.setCurrentDirectory(FileSystemView.getFileSystemView().getHomeDirectory());
            }
        }

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedDir = chooser.getSelectedFile();
            scriptTempDirField.setText(selectedDir.getAbsolutePath());
            setStatusLabel(scriptTempDirStatusLabel, true, "已选择");
        }
    }

    /**
     * 浏览Python路径
     */
    private void browsePythonPath() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择Python解释器");

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
            setStatusLabel(pythonStatusLabel, null, null);
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
            setStatusLabel(sqlmapStatusLabel, null, null);
        }
    }

    /**
     * 测试Python路径
     */
    private void testPythonPath() {
        pythonTestBtn.setEnabled(false);
        setStatusLabel(pythonStatusLabel, null, "测试中...");

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
                        setStatusLabel(pythonStatusLabel, true, version);
                        appendLog("[+] Python测试成功: " + version);
                        JOptionPane.showMessageDialog(CommandExecConfigPanel.this,
                            "Python测试成功!\n版本: " + version,
                            "测试成功", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        setStatusLabel(pythonStatusLabel, false, result.getMessage());
                        appendLog("[-] Python测试失败: " + result.getMessage());
                        JOptionPane.showMessageDialog(CommandExecConfigPanel.this,
                            "Python测试失败:\n" + result.getMessage(),
                            "测试失败", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    setStatusLabel(pythonStatusLabel, false, e.getMessage());
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
        setStatusLabel(sqlmapStatusLabel, null, "测试中...");

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
                        setStatusLabel(sqlmapStatusLabel, true, version);
                        appendLog("[+] SQLMap测试成功: " + version);
                        JOptionPane.showMessageDialog(CommandExecConfigPanel.this,
                            "SQLMap测试成功!\n版本: " + version,
                            "测试成功", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        setStatusLabel(sqlmapStatusLabel, false, result.getMessage());
                        appendLog("[-] SQLMap测试失败: " + result.getMessage());
                        JOptionPane.showMessageDialog(CommandExecConfigPanel.this,
                            "SQLMap测试失败:\n" + result.getMessage(),
                            "测试失败", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    setStatusLabel(sqlmapStatusLabel, false, e.getMessage());
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
        if (database == null) {
            return;
        }

        CommandExecConfig config = database.getCommandExecConfig();
        if (config == null) {
            config = CommandExecConfig.createDefault();
        }

        // 基础配置
        autoCopyCheckBox.setSelected(config.isAutoCopy());
        tempDirField.setText(config.getTempDir());
        scriptTempDirField.setText(config.getScriptTempDir());

        // 执行环境配置
        pythonPathField.setText(config.getPythonPath());
        sqlmapPathField.setText(config.getSqlmapPath());
        keepTerminalCheckBox.setSelected(config.isKeepTerminal());

        // 终端类型
        String savedType = config.getTerminalType();
        List<TerminalOption> options = SqlCommandBuilder.getTerminalOptions();
        for (int i = 0; i < options.size(); i++) {
            if (options.get(i).getType().name().equals(savedType)) {
                terminalComboBox.setSelectedIndex(i);
                break;
            }
        }

        // 加载标题规则配置到 ConfigManager 内存
        List<TitleRule> rules = config.getTitleRules();
        if (rules != null && !rules.isEmpty()) {
            configManager.setTitleRules(rules);
        }
        configManager.setTitleFallback(config.getTitleFallback());
        configManager.setTitleMaxLength(config.getTitleMaxLength());

        // 让 TitleRulesPanel 重新加载显示
        if (titleRulesPanel != null) {
            // TitleRulesPanel 在构造时会从 ConfigManager 加载
            // 这里需要触发重新加载
            titleRulesPanel.loadRules();
        }

        setStatusLabel(tempDirStatusLabel, true, "已加载");
        setStatusLabel(scriptTempDirStatusLabel, true, "已加载");
        setStatusLabel(terminalStatusLabel, true, "已加载");
    }

    /**
     * 保存配置
     */
    private void saveConfiguration() {
        if (database == null) {
            JOptionPane.showMessageDialog(this,
                "数据库未初始化，无法保存配置",
                "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String pythonPath = pythonPathField.getText().trim();
        String sqlmapPath = sqlmapPathField.getText().trim();
        String tempDir = tempDirField.getText().trim();
        String scriptTempDir = scriptTempDirField.getText().trim();
        TerminalOption selectedOption = (TerminalOption) terminalComboBox.getSelectedItem();

        // 验证SQLMap路径（必填）
        if (sqlmapPath.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "SQLMap路径为必填项，请配置sqlmap.py的路径",
                "配置不完整", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 验证临时目录
        if (!tempDir.isEmpty()) {
            File dir = new File(tempDir);
            if (!dir.exists()) {
                int result = JOptionPane.showConfirmDialog(this,
                    "目录不存在: " + tempDir + "\n是否创建该目录？",
                    "目录不存在",
                    JOptionPane.YES_NO_OPTION);
                if (result == JOptionPane.YES_OPTION) {
                    if (!dir.mkdirs()) {
                        HtmlMessageDialog.showError(this, "错误", "无法创建目录: " + tempDir);
                        return;
                    }
                } else {
                    return;
                }
            } else if (!dir.isDirectory()) {
                HtmlMessageDialog.showError(this, "错误", "路径不是目录: " + tempDir);
                return;
            }
        }

        // 验证脚本临时目录
        if (!scriptTempDir.isEmpty()) {
            File scriptDir = new File(scriptTempDir);
            if (!scriptDir.exists()) {
                int result = JOptionPane.showConfirmDialog(this,
                    "脚本目录不存在: " + scriptTempDir + "\n是否创建该目录？",
                    "目录不存在",
                    JOptionPane.YES_NO_OPTION);
                if (result == JOptionPane.YES_OPTION) {
                    if (!scriptDir.mkdirs()) {
                        HtmlMessageDialog.showError(this, "错误", "无法创建目录: " + scriptTempDir);
                        return;
                    }
                } else {
                    return;
                }
            } else if (!scriptDir.isDirectory()) {
                HtmlMessageDialog.showError(this, "错误", "路径不是目录: " + scriptTempDir);
                return;
            }
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

        // 构建配置对象
        CommandExecConfig config = new CommandExecConfig();
        config.setAutoCopy(autoCopyCheckBox.isSelected());
        config.setTempDir(tempDir);
        config.setScriptTempDir(scriptTempDir);
        config.setPythonPath(pythonPath);
        config.setSqlmapPath(sqlmapPath);
        config.setTerminalType(selectedOption != null ? selectedOption.getType().name() : "AUTO");
        config.setKeepTerminal(keepTerminalCheckBox.isSelected());

        // 保存标题规则配置到 ConfigManager 内存，并添加到 config 对象
        if (titleRulesPanel != null) {
            titleRulesPanel.saveConfiguration();
            // 把标题规则配置也添加到 config 对象中
            config.setTitleRules(titleRulesPanel.getCurrentRules());
            config.setTitleFallback(titleRulesPanel.getCurrentFallback());
            config.setTitleMaxLength(titleRulesPanel.getCurrentMaxLength());
        }

        // 保存到数据库
        boolean success = database.saveCommandExecConfig(config);
        if (success) {
            // 同步更新 ConfigManager
            syncToConfigManager(config);

            appendLog("[+] 命令行执行配置已保存");
            appendLog("    自动复制: " + (config.isAutoCopy() ? "是" : "否"));
            appendLog("    临时目录: " + (tempDir.isEmpty() ? "(系统默认)" : tempDir));
            appendLog("    脚本目录: " + (scriptTempDir.isEmpty() ? "(使用临时目录)" : scriptTempDir));
            appendLog("    Python路径: " + (pythonPath.isEmpty() ? "(系统默认)" : pythonPath));
            appendLog("    SQLMap路径: " + sqlmapPath);
            appendLog("    终端类型: " + (selectedOption != null ? selectedOption.getDisplayName() : "自动"));
            appendLog("    保持终端: " + (keepTerminalCheckBox.isSelected() ? "是" : "否"));

            setStatusLabel(tempDirStatusLabel, true, "已保存");
            setStatusLabel(scriptTempDirStatusLabel, true, "已保存");
            setStatusLabel(terminalStatusLabel, true, "已保存");

            HtmlMessageDialog.showInfo(this, "保存成功",
                "<h3 style='color: green;'>配置已保存</h3>" +
                "<p><b>自动复制:</b> " + (config.isAutoCopy() ? "是" : "否") + "</p>" +
                "<p><b>临时目录:</b> " + (tempDir.isEmpty() ? "系统默认" : tempDir) + "</p>" +
                "<p><b>脚本目录:</b> " + (scriptTempDir.isEmpty() ? "使用临时目录" : scriptTempDir) + "</p>" +
                "<p><b>Python路径:</b> " + (pythonPath.isEmpty() ? "系统默认" : pythonPath) + "</p>" +
                "<p><b>SQLMap路径:</b> " + sqlmapPath + "</p>" +
                "<p><b>终端类型:</b> " + (selectedOption != null ? selectedOption.getDisplayName() : "自动") + "</p>" +
                "<p><b>保持终端:</b> " + (keepTerminalCheckBox.isSelected() ? "是" : "否") + "</p>");
        } else {
            HtmlMessageDialog.showError(this, "保存失败", "无法保存配置到数据库");
        }
    }

    /**
     * 同步配置到 ConfigManager
     */
    private void syncToConfigManager(CommandExecConfig config) {
        configManager.setClipboardAutoCopy(config.isAutoCopy());
        configManager.setClipboardTempDir(config.getTempDir());
        configManager.setScriptTempDir(config.getScriptTempDir());
        configManager.setDirectPythonPath(config.getPythonPath());
        configManager.setDirectSqlmapPath(config.getSqlmapPath());
        
        try {
            TerminalType type = TerminalType.valueOf(config.getTerminalType());
            configManager.setDirectTerminalType(type);
        } catch (IllegalArgumentException e) {
            configManager.setDirectTerminalType(TerminalType.AUTO);
        }
        
        configManager.setDirectKeepTerminal(config.isKeepTerminal());
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

        // 重置基础配置
        autoCopyCheckBox.setSelected(true);
        tempDirField.setText("");
        scriptTempDirField.setText("");

        // 重置执行环境配置
        pythonPathField.setText("");
        sqlmapPathField.setText("");
        terminalComboBox.setSelectedIndex(0); // 自动检测
        keepTerminalCheckBox.setSelected(true);

        // 重置标题规则配置
        if (titleRulesPanel != null) {
            titleRulesPanel.resetToDefault();
        }

        setStatusLabel(tempDirStatusLabel, true, "已恢复默认");
        setStatusLabel(scriptTempDirStatusLabel, true, "已恢复默认");
        setStatusLabel(pythonStatusLabel, null, null);
        setStatusLabel(sqlmapStatusLabel, null, null);
        setStatusLabel(terminalStatusLabel, true, "已恢复默认");

        appendLog("[+] 命令行执行配置已恢复为默认值");
    }

    /**
     * 显示帮助对话框
     */
    private void showHelpDialog() {
        CommandExecHelpDialog.showDialog(this);
    }

    /**
     * 设置状态标签
     */
    private void setStatusLabel(JLabel label, Boolean success, String text) {
        if (label == null) return;
        
        if (success == null) {
            label.setText(text != null ? text : "");
            label.setForeground(Color.GRAY);
            label.setToolTipText(null);
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
