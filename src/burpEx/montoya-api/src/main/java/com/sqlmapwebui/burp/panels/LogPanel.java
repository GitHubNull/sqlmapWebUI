package com.sqlmapwebui.burp.panels;

import javax.swing.*;
import java.awt.*;

/**
 * 日志面板
 * 显示活动日志
 */
public class LogPanel extends JPanel {
    
    private JTextArea logArea;
    
    public LogPanel() {
        initializePanel();
    }
    
    private void initializePanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(200, 200, 200));
        logArea.setCaretColor(Color.WHITE);
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("活动日志"));
        add(scrollPane, BorderLayout.CENTER);
        
        // Log controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton clearLogButton = new JButton("清空日志");
        clearLogButton.addActionListener(e -> logArea.setText(""));
        controlPanel.add(clearLogButton);
        
        add(controlPanel, BorderLayout.SOUTH);
    }
    
    /**
     * 追加日志消息
     */
    public void appendLog(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")
            ) + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
}
