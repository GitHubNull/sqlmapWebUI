package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.SqlmapApiClient;
import com.sqlmapwebui.burp.util.SqlCommandBuilder;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.io.File;
import java.util.function.Consumer;

/**
 * 剪贴板功能配置面板
 * 管理右键菜单"复制SQLMap命令"功能的配置
 */
public class ClipboardConfigPanel extends BaseConfigPanel {

    private JCheckBox autoCopyCheckBox;
    private JTextField tempDirField;
    private JButton browseButton;
    private JLabel statusLabel;

    public ClipboardConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient, Consumer<String> logAppender) {
        super(configManager, apiClient, logAppender);
    }

    @Override
    protected void initializePanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));

        // 配置表单
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("剪贴板功能配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // 功能说明
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JTextArea descArea = new JTextArea(
            "此功能允许您在右键菜单中「复制SQLMap命令」到剪贴板，" +
            "生成的命令使用 -r 参数指定HTTP请求文件，您可以在任意终端中执行该命令。");
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
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(new JSeparator(), gbc);
        row++;

        // 自动复制选项
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.NONE;
        JPanel autoCopyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        autoCopyCheckBox = new JCheckBox("自动复制到剪贴板", true);
        autoCopyCheckBox.setToolTipText("勾选后，生成命令时会自动复制到剪贴板；取消勾选则会显示预览对话框");
        autoCopyPanel.add(autoCopyCheckBox);
        formPanel.add(autoCopyPanel, gbc);
        row++;

        // 临时文件目录配置
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("临时文件目录:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        JPanel tempDirPanel = new JPanel(new BorderLayout(5, 0));
        tempDirField = new JTextField(30);
        tempDirField.setToolTipText("设置保存HTTP请求文件的目录，留空则使用系统默认临时目录");
        tempDirPanel.add(tempDirField, BorderLayout.CENTER);

        browseButton = new JButton("浏览...");
        browseButton.addActionListener(e -> browseTempDir());
        tempDirPanel.add(browseButton, BorderLayout.EAST);

        formPanel.add(tempDirPanel, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        statusLabel = new JLabel();
        statusLabel.setPreferredSize(new Dimension(20, 20));
        formPanel.add(statusLabel, gbc);
        row++;

        // 说明文字
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        JLabel hintLabel = new JLabel("提示: 留空使用系统默认临时目录，命令中的路径会自动处理空格");
        hintLabel.setForeground(new Color(100, 100, 100));
        hintLabel.setFont(hintLabel.getFont().deriveFont(Font.ITALIC, 11f));
        formPanel.add(hintLabel, gbc);
        row++;

        // 按钮面板
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
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
        SqlCommandBuilder.OsType osType = SqlCommandBuilder.detectOs();
        String osName;
        switch (osType) {
            case WINDOWS: osName = "Windows"; break;
            case MACOS: osName = "macOS"; break;
            case LINUX: osName = "Linux"; break;
            default: osName = "未知"; break;
        }

        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 5px; }" +
            "h3 { color: #2c3e50; margin: 10px 0 5px 0; border-bottom: 1px solid #bdc3c7; padding-bottom: 3px; }" +
            "ul { margin: 3px 0 8px 20px; padding: 0; }" +
            "li { margin: 2px 0; }" +
            ".code { font-family: 'Consolas', monospace; background: #ecf0f1; padding: 1px 4px; border-radius: 3px; }" +
            ".info { color: #3498db; }" +
            ".os { color: #27ae60; font-weight: bold; }" +
            "</style></head><body>" +

            "<h3>📋 功能说明</h3>" +
            "<ul>" +
            "<li>在Burp的HTTP请求上<strong>右键</strong>，选择 <span class='code'>复制SQLMap命令</span></li>" +
            "<li>生成的命令会使用 <span class='code'>-r</span> 参数指定HTTP请求文件</li>" +
            "<li>临时文件会保存在配置的目录中，命令中包含完整的文件路径</li>" +
            "</ul>" +

            "<h3>🖥️ 当前操作系统</h3>" +
            "<p>检测到: <span class='os'>" + osName + "</span></p>" +

            "<h3>💡 使用步骤</h3>" +
            "<ol>" +
            "<li>在Burp中选择要测试的HTTP请求</li>" +
            "<li>右键点击 <span class='code'>复制SQLMap命令</span></li>" +
            "<li>打开终端（CMD、PowerShell或Terminal）</li>" +
            "<li>粘贴命令并执行（确保已安装Python和SQLMap）</li>" +
            "</ol>" +

            "<h3>⚙️ 配置选项</h3>" +
            "<ul>" +
            "<li><b>自动复制到剪贴板</b>：勾选后自动复制，无需确认</li>" +
            "<li><b>临时文件目录</b>：指定HTTP请求文件的保存位置</li>" +
            "</ul>" +

            "<h3>⚠️ 注意事项</h3>" +
            "<ul>" +
            "<li>确保已安装Python并配置好环境变量</li>" +
            "<li>确保已下载SQLMap并知道其路径</li>" +
            "<li>临时文件在使用后可以手动删除</li>" +
            "</ul>" +

            "</body></html>";
    }

    /**
     * 浏览临时目录
     */
    private void browseTempDir() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("选择临时文件目录");

        // 设置初始目录
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
            setStatus(true, "已选择目录");
        }
    }

    /**
     * 加载配置
     */
    private void loadConfiguration() {
        autoCopyCheckBox.setSelected(configManager.isClipboardAutoCopy());
        tempDirField.setText(configManager.getClipboardTempDir());
        setStatus(true, "配置已加载");
    }

    /**
     * 保存配置
     */
    private void saveConfiguration() {
        boolean autoCopy = autoCopyCheckBox.isSelected();
        String tempDir = tempDirField.getText().trim();

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

        configManager.setClipboardAutoCopy(autoCopy);
        configManager.setClipboardTempDir(tempDir);

        appendLog("[+] 剪贴板配置已保存: 自动复制=" + autoCopy + ", 临时目录=" + (tempDir.isEmpty() ? "(系统默认)" : tempDir));
        setStatus(true, "已保存");

        HtmlMessageDialog.showInfo(this, "保存成功",
            "<h3 style='color: green;'>✓ 配置已保存</h3>" +
            "<p><b>自动复制:</b> " + (autoCopy ? "是" : "否") + "</p>" +
            "<p><b>临时目录:</b> " + (tempDir.isEmpty() ? "系统默认" : tempDir) + "</p>");
    }

    /**
     * 恢复默认设置
     */
    private void resetToDefault() {
        int result = JOptionPane.showConfirmDialog(this,
            "确定要恢复默认设置吗？",
            "确认重置",
            JOptionPane.YES_NO_OPTION);

        if (result != JOptionPane.YES_OPTION) {
            return;
        }

        autoCopyCheckBox.setSelected(true);
        tempDirField.setText("");

        appendLog("[+] 剪贴板配置已恢复为默认值");
        setStatus(true, "已恢复默认");
    }

    /**
     * 设置状态图标
     */
    private void setStatus(boolean success, String tooltip) {
        if (success) {
            statusLabel.setText("✓");
            statusLabel.setForeground(new Color(39, 174, 96));
        } else {
            statusLabel.setText("✗");
            statusLabel.setForeground(new Color(231, 76, 60));
        }
        statusLabel.setToolTipText(tooltip);
    }
}
