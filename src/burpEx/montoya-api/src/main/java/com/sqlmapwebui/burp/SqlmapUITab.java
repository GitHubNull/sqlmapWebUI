package com.sqlmapwebui.burp;

import burp.api.montoya.MontoyaApi;
import com.sqlmapwebui.burp.panels.*;
import com.sqlmapwebui.burp.dialogs.AboutDialog;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

/**
 * UI Tab for SQLMap WebUI Extension (Montoya API)
 * 
 * 功能：
 * 1. 服务器配置
 * 2. 默认扫描配置
 * 3. 常用配置管理
 * 4. 历史配置管理
 * 5. 活动日志
 * 
 * 采用模块化设计，各功能面板独立实现
 */
public class SqlmapUITab extends JPanel {
    
    @SuppressWarnings("unused")
    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final ConfigManager configManager;
    private final Consumer<String> onBackendUrlChange;
    
    // 面板组件
    private ServerConfigPanel serverConfigPanel;
    private DefaultConfigPanel defaultConfigPanel;
    private PresetConfigPanel presetConfigPanel;
    private HistoryConfigPanel historyConfigPanel;
    private LogPanel logPanel;
    
    // 状态标签
    private JLabel statusLabel;
    
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
        
        // 创建日志面板（需要先创建，供其他面板使用）
        logPanel = new LogPanel();
        
        // 创建选项卡面板
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Tab 1: 服务器配置
        serverConfigPanel = new ServerConfigPanel(
            configManager, 
            apiClient, 
            this::appendLog,
            onBackendUrlChange,
            this::updateConnectionStatus
        );
        tabbedPane.addTab("服务器配置", serverConfigPanel);
        
        // Tab 2: 默认配置
        defaultConfigPanel = new DefaultConfigPanel(configManager, apiClient, this::appendLog);
        tabbedPane.addTab("默认配置", defaultConfigPanel);
        
        // Tab 3: 常用配置管理
        presetConfigPanel = new PresetConfigPanel(configManager, apiClient, this::appendLog);
        tabbedPane.addTab("常用配置", presetConfigPanel);
        
        // 将常用配置数据库传递给默认配置面板
        defaultConfigPanel.setPresetDatabase(presetConfigPanel.getDatabase());
        
        // Tab 4: 历史配置管理
        historyConfigPanel = new HistoryConfigPanel(configManager, apiClient, this::appendLog);
        tabbedPane.addTab("历史配置", historyConfigPanel);
        
        // Tab 5: 活动日志
        tabbedPane.addTab("活动日志", logPanel);
        
        add(tabbedPane, BorderLayout.CENTER);
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
        
        // 右侧面板：包含状态标签和帮助按钮
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        
        statusLabel = new JLabel("● 未连接");
        statusLabel.setForeground(Color.RED);
        statusLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        rightPanel.add(statusLabel);
        
        // 帮助按钮
        JButton helpButton = new JButton("帮助/关于");
        helpButton.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        helpButton.addActionListener(e -> AboutDialog.showDialog(this));
        rightPanel.add(helpButton);
        
        panel.add(rightPanel, BorderLayout.EAST);
        
        return panel;
    }
    
    /**
     * 更新连接状态
     */
    private void updateConnectionStatus(boolean connected) {
        SwingUtilities.invokeLater(() -> {
            if (connected) {
                statusLabel.setText("● 已连接");
                statusLabel.setForeground(new Color(0, 150, 0));
            } else {
                statusLabel.setText("● 未连接");
                statusLabel.setForeground(Color.RED);
            }
        });
    }
    
    /**
     * Append message to log area
     */
    public void appendLog(String message) {
        logPanel.appendLog(message);
    }
    
    /**
     * 获取配置管理器
     */
    public ConfigManager getConfigManager() {
        return configManager;
    }
    
    /**
     * 刷新历史配置表格
     */
    public void refreshHistoryTable() {
        if (historyConfigPanel != null) {
            historyConfigPanel.refreshHistoryTable();
        }
    }
    
    /**
     * 刷新常用配置表格
     */
    public void refreshPresetTable() {
        if (presetConfigPanel != null) {
            presetConfigPanel.refreshTable();
        }
    }
    
    /**
     * 获取常用配置数据库
     */
    public PresetConfigDatabase getPresetDatabase() {
        if (presetConfigPanel != null) {
            return presetConfigPanel.getDatabase();
        }
        return null;
    }
}
