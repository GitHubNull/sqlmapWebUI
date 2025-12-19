package com.sqlmapwebui.burp.panels;

import javax.swing.*;
import java.awt.*;

/**
 * 支持HTML的消息弹窗组件
 * 替代JOptionPane以支持富文本显示
 */
public class HtmlMessageDialog {
    
    /**
     * 显示信息弹窗
     */
    public static void showInfo(Component parent, String title, String htmlContent) {
        showDialog(parent, title, htmlContent, JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 显示警告弹窗
     */
    public static void showWarning(Component parent, String title, String htmlContent) {
        showDialog(parent, title, htmlContent, JOptionPane.WARNING_MESSAGE);
    }
    
    /**
     * 显示错误弹窗
     */
    public static void showError(Component parent, String title, String htmlContent) {
        showDialog(parent, title, htmlContent, JOptionPane.ERROR_MESSAGE);
    }
    
    /**
     * 显示确认弹窗
     * @return true 如果用户点击了确定
     */
    public static boolean showConfirm(Component parent, String title, String htmlContent) {
        return showConfirmDialog(parent, title, htmlContent, JOptionPane.QUESTION_MESSAGE);
    }
    
    /**
     * 显示弹窗
     */
    private static void showDialog(Component parent, String title, String htmlContent, int messageType) {
        JDialog dialog = createDialog(parent, title, htmlContent, messageType, false);
        dialog.setVisible(true);
    }
    
    /**
     * 显示确认弹窗
     */
    private static boolean showConfirmDialog(Component parent, String title, String htmlContent, int messageType) {
        final boolean[] result = {false};
        
        JDialog dialog = new JDialog(getParentFrame(parent), title, true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        
        // 创建内容面板
        JPanel contentPanel = createContentPanel(htmlContent, messageType);
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        
        JButton yesButton = new JButton("确定");
        yesButton.addActionListener(e -> {
            result[0] = true;
            dialog.dispose();
        });
        buttonPanel.add(yesButton);
        
        JButton noButton = new JButton("取消");
        noButton.addActionListener(e -> {
            result[0] = false;
            dialog.dispose();
        });
        buttonPanel.add(noButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.pack();
        dialog.setMinimumSize(new Dimension(350, 200));
        dialog.setLocationRelativeTo(parent);
        dialog.setVisible(true);
        
        return result[0];
    }
    
    /**
     * 创建弹窗
     */
    private static JDialog createDialog(Component parent, String title, String htmlContent, int messageType, boolean isConfirm) {
        JDialog dialog = new JDialog(getParentFrame(parent), title, true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        
        // 创建内容面板
        JPanel contentPanel = createContentPanel(htmlContent, messageType);
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        
        JButton okButton = new JButton("确定");
        okButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(okButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.pack();
        dialog.setMinimumSize(new Dimension(350, 180));
        dialog.setLocationRelativeTo(parent);
        
        return dialog;
    }
    
    /**
     * 创建内容面板
     */
    private static JPanel createContentPanel(String htmlContent, int messageType) {
        JPanel panel = new JPanel(new BorderLayout(15, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 10, 15));
        
        // 图标
        Icon icon = getIcon(messageType);
        if (icon != null) {
            JLabel iconLabel = new JLabel(icon);
            iconLabel.setVerticalAlignment(SwingConstants.TOP);
            panel.add(iconLabel, BorderLayout.WEST);
        }
        
        // HTML内容
        JEditorPane editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setEditable(false);
        editorPane.setOpaque(false);
        editorPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        editorPane.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        
        // 包装HTML内容
        String wrappedHtml = wrapHtmlContent(htmlContent);
        editorPane.setText(wrappedHtml);
        editorPane.setCaretPosition(0);
        
        // 使用滚动面板以支持长内容
        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setPreferredSize(new Dimension(350, 150));
        scrollPane.getViewport().setOpaque(false);
        scrollPane.setOpaque(false);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 包装HTML内容，添加默认样式
     */
    private static String wrapHtmlContent(String content) {
        // 如果已经是完整的HTML，直接返回
        if (content.toLowerCase().startsWith("<html>")) {
            return content;
        }
        
        // 否则包装成HTML
        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 0; padding: 0; }" +
            "h3 { margin: 5px 0; }" +
            "p { margin: 5px 0; }" +
            "ul { margin: 5px 0 5px 20px; padding: 0; }" +
            "li { margin: 2px 0; }" +
            "hr { border: none; border-top: 1px solid #ccc; margin: 8px 0; }" +
            ".success { color: #27ae60; }" +
            ".error { color: #e74c3c; }" +
            ".warning { color: #f39c12; }" +
            "</style></head><body>" + content + "</body></html>";
    }
    
    /**
     * 获取对应类型的图标
     */
    private static Icon getIcon(int messageType) {
        switch (messageType) {
            case JOptionPane.INFORMATION_MESSAGE:
                return UIManager.getIcon("OptionPane.informationIcon");
            case JOptionPane.WARNING_MESSAGE:
                return UIManager.getIcon("OptionPane.warningIcon");
            case JOptionPane.ERROR_MESSAGE:
                return UIManager.getIcon("OptionPane.errorIcon");
            case JOptionPane.QUESTION_MESSAGE:
                return UIManager.getIcon("OptionPane.questionIcon");
            default:
                return null;
        }
    }
    
    /**
     * 获取父窗口Frame
     */
    private static Frame getParentFrame(Component parent) {
        if (parent == null) {
            return null;
        }
        if (parent instanceof Frame) {
            return (Frame) parent;
        }
        return (Frame) SwingUtilities.getWindowAncestor(parent);
    }
}
