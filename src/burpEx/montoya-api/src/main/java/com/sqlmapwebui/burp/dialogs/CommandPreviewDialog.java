package com.sqlmapwebui.burp.dialogs;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.util.CommandExecutor;
import com.sqlmapwebui.burp.util.SqlCommandBuilder;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;

/**
 * 命令预览对话框
 * 用于显示生成的SQLMap命令，并允许用户复制或执行
 */
public class CommandPreviewDialog {

    private final ConfigManager configManager;

    public CommandPreviewDialog(ConfigManager configManager) {
        this.configManager = configManager;
    }

    /**
     * 显示命令预览对话框（仅复制模式）
     *
     * @param parent 父组件
     * @param command SQLMap命令
     * @param requestFilePath 请求文件路径（可为null）
     */
    public void showCopyDialog(Component parent, String command, String requestFilePath) {
        showDialogInternal(parent, command, requestFilePath, false);
    }

    /**
     * 显示命令预览对话框（执行模式）
     *
     * @param parent 父组件
     * @param command SQLMap命令
     * @param requestFilePath 请求文件路径（可为null）
     */
    public void showExecuteDialog(Component parent, String command, String requestFilePath) {
        showDialogInternal(parent, command, requestFilePath, true);
    }

    /**
     * 内部显示对话框实现
     */
    private void showDialogInternal(Component parent, String command, String requestFilePath, boolean isExecuteMode) {
        String title = isExecuteMode ? "执行SQLMap命令" : "SQLMap命令预览";

        JDialog dialog = new JDialog((Frame) null, title, true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(700, 400);
        dialog.setLocationRelativeTo(parent);

        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 说明标签
        JPanel headerPanel = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel(isExecuteMode ?
            "<html><b>即将执行的SQLMap命令:</b></html>" :
            "<html><b>生成的SQLMap命令:</b></html>");
        headerPanel.add(titleLabel, BorderLayout.WEST);

        if (requestFilePath != null) {
            JLabel filePathLabel = new JLabel("<html><span style='color:gray;'>请求文件: " +
                new File(requestFilePath).getName() + "</span></html>");
            headerPanel.add(filePathLabel, BorderLayout.EAST);
        }
        contentPanel.add(headerPanel, BorderLayout.NORTH);

        // 命令显示区
        JPanel commandPanel = new JPanel(new BorderLayout());
        commandPanel.setBorder(BorderFactory.createTitledBorder("SQLMap命令"));

        JTextArea commandArea = new JTextArea(command);
        commandArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        commandArea.setLineWrap(true);
        commandArea.setWrapStyleWord(true);
        commandArea.setEditable(true);
        commandArea.setRows(5);

        JScrollPane scrollPane = new JScrollPane(commandArea);
        commandPanel.add(scrollPane, BorderLayout.CENTER);

        // 提示信息
        JLabel hintLabel = new JLabel("<html><span style='color:gray;'>" +
            "提示: 可以在上方编辑框中修改命令参数后再复制/执行</span></html>");
        hintLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        commandPanel.add(hintLabel, BorderLayout.SOUTH);

        contentPanel.add(commandPanel, BorderLayout.CENTER);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));

        if (isExecuteMode) {
            JButton executeButton = new JButton("立即执行");
            executeButton.addActionListener(e -> {
                String editedCommand = commandArea.getText().trim();
                executeCommand(dialog, editedCommand);
            });
            buttonPanel.add(executeButton);

            JButton copyAndCloseButton = new JButton("复制并关闭");
            copyAndCloseButton.addActionListener(e -> {
                String editedCommand = commandArea.getText().trim();
                CommandExecutor.copyToClipboard(editedCommand);
                dialog.dispose();
            });
            buttonPanel.add(copyAndCloseButton);
        } else {
            JButton copyButton = new JButton("复制到剪贴板");
            copyButton.addActionListener(e -> {
                String editedCommand = commandArea.getText().trim();
                CommandExecutor.copyToClipboard(editedCommand);
                JOptionPane.showMessageDialog(dialog,
                    "命令已复制到剪贴板!",
                    "复制成功", JOptionPane.INFORMATION_MESSAGE);
            });
            buttonPanel.add(copyButton);

            JButton copyAndCloseButton = new JButton("复制并关闭");
            copyAndCloseButton.addActionListener(e -> {
                String editedCommand = commandArea.getText().trim();
                CommandExecutor.copyToClipboard(editedCommand);
                dialog.dispose();
            });
            buttonPanel.add(copyAndCloseButton);
        }

        JButton closeButton = new JButton("关闭");
        closeButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeButton);

        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        // 添加文件路径信息
        if (requestFilePath != null) {
            JPanel infoPanel = new JPanel(new BorderLayout());
            infoPanel.setBorder(BorderFactory.createTitledBorder("临时文件信息"));

            JPanel infoContent = new JPanel(new GridLayout(2, 1, 5, 5));
            infoContent.add(new JLabel("请求文件路径: " + requestFilePath));
            infoContent.add(new JLabel("<html><span style='color:gray;'>" +
                "提示: 临时文件在使用后可手动删除</span></html>"));
            infoPanel.add(infoContent, BorderLayout.CENTER);

            contentPanel.add(infoPanel, BorderLayout.EAST);
        }

        dialog.add(contentPanel);
        dialog.getRootPane().setDefaultButton(
            isExecuteMode ? (JButton) buttonPanel.getComponent(0) : (JButton) buttonPanel.getComponent(0));

        // ESC键关闭对话框
        dialog.getRootPane().registerKeyboardAction(
            e -> dialog.dispose(),
            KeyStroke.getKeyStroke("ESCAPE"),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

        dialog.setVisible(true);
    }

    /**
     * 执行命令
     */
    private void executeCommand(JDialog dialog, String command) {
        ConfigManager.TerminalType terminalType = configManager.getDirectTerminalType();
        boolean keepTerminal = configManager.isDirectKeepTerminal();
        String scriptTempDir = configManager.getScriptTempDir();

        // 使用默认标题 "SQLMap"
        CommandExecutor.ExecutionResult result = CommandExecutor.executeInTerminal(
            command, terminalType, keepTerminal, "SQLMap", scriptTempDir);

        if (result.isSuccess()) {
            dialog.dispose();
            JOptionPane.showMessageDialog(null,
                "命令已在终端中启动!\n\n提示: 终端窗口会独立运行，您可以继续使用Burp。",
                "执行成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(dialog,
                "启动终端失败:\n\n" + result.getMessage(),
                "执行失败", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 显示简单的复制成功提示
     */
    public static void showCopySuccess(Component parent) {
        JOptionPane.showMessageDialog(parent,
            "SQLMap命令已复制到剪贴板!",
            "复制成功", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 显示简单的执行成功提示
     */
    public static void showExecuteSuccess(Component parent) {
        JOptionPane.showMessageDialog(parent,
            "SQLMap命令已在终端中启动!",
            "执行成功", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 显示错误提示
     */
    public static void showError(Component parent, String title, String message) {
        JOptionPane.showMessageDialog(parent,
            message, title, JOptionPane.ERROR_MESSAGE);
    }

    /**
     * 显示配置缺失警告
     */
    public static boolean showConfigWarning(Component parent, String missingConfig) {
        int result = JOptionPane.showConfirmDialog(parent,
            "配置不完整\n\n缺少必要配置: " + missingConfig + "\n\n是否现在去配置?",
            "配置警告", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        return result == JOptionPane.YES_OPTION;
    }

    /**
     * 快速显示复制对话框（静态方法）
     */
    public static void quickShowCopy(Component parent, String command, String requestFilePath) {
        CommandPreviewDialog dialog = new CommandPreviewDialog(null);
        dialog.showCopyDialog(parent, command, requestFilePath);
    }

    /**
     * 快速显示执行对话框（静态方法）
     */
    public static void quickShowExecute(Component parent, String command, String requestFilePath, ConfigManager configManager) {
        CommandPreviewDialog dialog = new CommandPreviewDialog(configManager);
        dialog.showExecuteDialog(parent, command, requestFilePath);
    }
}
