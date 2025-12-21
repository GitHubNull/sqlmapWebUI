package com.sqlmapwebui.burp.dialogs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlmapwebui.burp.SqlmapApiClient;
import com.sqlmapwebui.burp.SqlmapUITab;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 会话Header对话框
 */
public class SessionHeaderDialog {
    
    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final SqlmapUITab uiTab;
    
    public SessionHeaderDialog(MontoyaApi api, SqlmapApiClient apiClient, SqlmapUITab uiTab) {
        this.api = api;
        this.apiClient = apiClient;
        this.uiTab = uiTab;
    }
    
    /**
     * 显示会话Header配置对话框
     */
    public void show(HttpRequest request) {
        JDialog dialog = new JDialog((Frame) null, "提交会话Header", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(900, 700);
        dialog.setLocationRelativeTo(null);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 说明面板
        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder("使用说明"));
        JEditorPane helpPane = new JEditorPane();
        helpPane.setContentType("text/html");
        helpPane.setEditable(false);
        helpPane.setOpaque(false);
        helpPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        helpPane.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        helpPane.setText(
            "<html><body style='font-family:sans-serif;'>" +
            "<b>选择要提交的会话相关Header字段</b><br>" +
            "常见会话Header（如Cookie、Authorization等）已默认勾选<br>" +
            "<span style='color:gray;'>提示: 会话Header将临时存储，用于后续的扫描任务</span>" +
            "</body></html>"
        );
        helpPanel.add(helpPane, BorderLayout.CENTER);
        contentPanel.add(helpPanel, BorderLayout.NORTH);
        
        // 中间部分: Header选择列表
        JPanel headerSelectionPanel = new JPanel(new BorderLayout(5, 5));
        headerSelectionPanel.setBorder(BorderFactory.createTitledBorder("请求Header列表"));
        
        // 提取请求头
        List<String[]> headerItems = new ArrayList<>();
        request.headers().forEach(header -> {
            headerItems.add(new String[]{header.name(), header.value()});
        });
        
        // 创建表格模型
        String[] columnNames = {"选择", "Header名称", "Header值"};
        Object[][] tableData = new Object[headerItems.size()][3];
        for (int i = 0; i < headerItems.size(); i++) {
            String headerName = headerItems.get(i)[0];
            String headerValue = headerItems.get(i)[1];
            boolean isSessionHeader = HeaderConstants.isCommonSessionHeader(headerName);
            tableData[i] = new Object[]{isSessionHeader, headerName, headerValue};
        }
        
        DefaultTableModel tableModel = new DefaultTableModel(tableData, columnNames) {
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        
        JTable headerTable = new JTable(tableModel);
        headerTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        headerTable.getColumnModel().getColumn(0).setMaxWidth(60);
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        headerTable.getColumnModel().getColumn(2).setPreferredWidth(400);
        headerTable.setRowHeight(24);
        
        JScrollPane tableScrollPane = new JScrollPane(headerTable);
        headerSelectionPanel.add(tableScrollPane, BorderLayout.CENTER);
        
        // 全选/取消全选按钮
        JPanel tableButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selectAllBtn = new JButton("全选");
        selectAllBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(true, i, 0);
            }
        });
        JButton deselectAllBtn = new JButton("取消全选");
        deselectAllBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(false, i, 0);
            }
        });
        JButton selectSessionBtn = new JButton("只选会话Header");
        selectSessionBtn.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                String name = (String) tableModel.getValueAt(i, 1);
                boolean isSession = HeaderConstants.isCommonSessionHeader(name);
                tableModel.setValueAt(isSession, i, 0);
            }
        });
        tableButtonPanel.add(selectAllBtn);
        tableButtonPanel.add(deselectAllBtn);
        tableButtonPanel.add(selectSessionBtn);
        headerSelectionPanel.add(tableButtonPanel, BorderLayout.SOUTH);
        
        contentPanel.add(headerSelectionPanel, BorderLayout.CENTER);
        
        // 作用域配置面板
        JPanel scopePanel = createScopePanel(request);
        contentPanel.add(scopePanel, BorderLayout.SOUTH);
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        // 从scopePanel提取组件引用
        JCheckBox enableScopeCheck = findComponentByType(scopePanel, "enableScopeCheck", JCheckBox.class);
        JComboBox<?> protocolCombo = findComponentByType(scopePanel, "protocolCombo", JComboBox.class);
        JTextField hostField = findComponentByType(scopePanel, "hostField", JTextField.class);
        JTextField pathField = findComponentByType(scopePanel, "pathField", JTextField.class);
        JCheckBox useRegexCheck = findComponentByType(scopePanel, "useRegexCheck", JCheckBox.class);
        JSpinner ttlSpinner = findComponentByType(scopePanel, "ttlSpinner", JSpinner.class);
        JComboBox<?> strategyCombo = findComponentByType(scopePanel, "strategyCombo", JComboBox.class);
        JSpinner prioritySpinner = findComponentByType(scopePanel, "prioritySpinner", JSpinner.class);
        
        // 底部按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton submitButton = new JButton("提交");
        submitButton.addActionListener(e -> {
            List<String[]> selectedHeaders = new ArrayList<>();
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                Boolean selected = (Boolean) tableModel.getValueAt(i, 0);
                if (selected != null && selected) {
                    String name = (String) tableModel.getValueAt(i, 1);
                    String value = (String) tableModel.getValueAt(i, 2);
                    selectedHeaders.add(new String[]{name, value});
                }
            }
            
            if (selectedHeaders.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "请至少选择一个Header字段", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            String scopeJson = "null";
            if (enableScopeCheck.isSelected()) {
                Object protocolObj = protocolCombo.getSelectedItem();
                String protocol = protocolObj != null ? protocolObj.toString() : "";
                String host = hostField.getText().trim();
                String path = pathField.getText().trim();
                boolean useRegex = useRegexCheck.isSelected();
                
                scopeJson = String.format(
                    "{\"protocol_pattern\":\"%s\",\"host_pattern\":\"%s\",\"path_pattern\":\"%s\",\"use_regex\":%s}",
                    JsonUtils.escapeJson(protocol), JsonUtils.escapeJson(host), JsonUtils.escapeJson(path), useRegex
                );
            }
            
            int ttl = (Integer) ttlSpinner.getValue();
            Object strategyObj = strategyCombo.getSelectedItem();
            String strategy = strategyObj != null ? strategyObj.toString() : "REPLACE";
            int priority = (Integer) prioritySpinner.getValue();
            
            sendSessionHeadersToBackend(selectedHeaders, scopeJson, ttl, strategy, priority);
            dialog.dispose();
        });
        buttonPanel.add(submitButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(cancelButton);
        
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }
    
    /**
     * 创建作用域配置面板
     */
    private JPanel createScopePanel(HttpRequest request) {
        JPanel scopePanel = new JPanel(new GridBagLayout());
        scopePanel.setBorder(BorderFactory.createTitledBorder("作用域配置（可选）"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        String hostFromRequest = "";
        try {
            java.net.URL urlObj = new java.net.URL(request.url());
            hostFromRequest = urlObj.getHost();
        } catch (Exception e) {
            hostFromRequest = "";
        }
        
        JCheckBox enableScopeCheck = new JCheckBox("启用作用域限制");
        enableScopeCheck.setName("enableScopeCheck");
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        scopePanel.add(enableScopeCheck, gbc);
        
        JLabel protocolLabel = new JLabel("协议:");
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1; gbc.weightx = 0;
        scopePanel.add(protocolLabel, gbc);
        JComboBox<String> protocolCombo = new JComboBox<>(new String[]{"", "http", "https"});
        protocolCombo.setName("protocolCombo");
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(protocolCombo, gbc);
        
        JLabel hostLabel = new JLabel("主机名模式:");
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        scopePanel.add(hostLabel, gbc);
        JTextField hostField = new JTextField(hostFromRequest);
        hostField.setName("hostField");
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(hostField, gbc);
        
        JLabel pathLabel = new JLabel("路径模式:");
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        scopePanel.add(pathLabel, gbc);
        JTextField pathField = new JTextField();
        pathField.setName("pathField");
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(pathField, gbc);
        
        JCheckBox useRegexCheck = new JCheckBox("使用正则表达式");
        useRegexCheck.setName("useRegexCheck");
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        scopePanel.add(useRegexCheck, gbc);
        
        JLabel ttlLabel = new JLabel("生存时间(秒):");
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1; gbc.weightx = 0;
        scopePanel.add(ttlLabel, gbc);
        JSpinner ttlSpinner = new JSpinner(new SpinnerNumberModel(3600, 60, 86400, 60));
        ttlSpinner.setName("ttlSpinner");
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(ttlSpinner, gbc);
        
        JLabel strategyLabel = new JLabel("替换策略:");
        gbc.gridx = 0; gbc.gridy = 6; gbc.weightx = 0;
        scopePanel.add(strategyLabel, gbc);
        JComboBox<String> strategyCombo = new JComboBox<>(new String[]{"REPLACE", "APPEND", "PREPEND", "UPSERT"});
        strategyCombo.setName("strategyCombo");
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(strategyCombo, gbc);
        
        JLabel priorityLabel = new JLabel("优先级(0-100):");
        gbc.gridx = 0; gbc.gridy = 7; gbc.weightx = 0;
        scopePanel.add(priorityLabel, gbc);
        JSpinner prioritySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 100, 1));
        prioritySpinner.setName("prioritySpinner");
        gbc.gridx = 1; gbc.weightx = 1;
        scopePanel.add(prioritySpinner, gbc);
        
        // 禁用/启用作用域字段
        protocolLabel.setEnabled(false);
        protocolCombo.setEnabled(false);
        hostLabel.setEnabled(false);
        hostField.setEnabled(false);
        pathLabel.setEnabled(false);
        pathField.setEnabled(false);
        useRegexCheck.setEnabled(false);
        
        enableScopeCheck.addActionListener(e -> {
            boolean enabled = enableScopeCheck.isSelected();
            protocolLabel.setEnabled(enabled);
            protocolCombo.setEnabled(enabled);
            hostLabel.setEnabled(enabled);
            hostField.setEnabled(enabled);
            pathLabel.setEnabled(enabled);
            pathField.setEnabled(enabled);
            useRegexCheck.setEnabled(enabled);
        });
        
        return scopePanel;
    }
    
    /**
     * 根据名称查找组件
     */
    private Component findComponentByName(Container container, String name) {
        for (Component c : container.getComponents()) {
            if (name.equals(c.getName())) {
                return c;
            }
            if (c instanceof Container) {
                Component result = findComponentByName((Container) c, name);
                if (result != null) return result;
            }
        }
        return null;
    }
    
    /**
     * 根据名称和类型安全地查找组件
     * @param container 容器
     * @param name 组件名称
     * @param type 期望的组件类型
     * @return 找到的组件，如果未找到或类型不匹配则返回null
     */
    private <T extends Component> T findComponentByType(Container container, String name, Class<T> type) {
        Component component = findComponentByName(container, name);
        if (component != null && type.isInstance(component)) {
            return type.cast(component);
        }
        return null;
    }
    
    /**
     * 发送会话Header到后端
     */
    private void sendSessionHeadersToBackend(List<String[]> headers, String scopeJson, 
                                              int ttl, String strategy, int priority) {
        try {
            StringBuilder headersArrayJson = new StringBuilder("[");
            for (int i = 0; i < headers.size(); i++) {
                String[] header = headers.get(i);
                if (i > 0) headersArrayJson.append(",");
                headersArrayJson.append(String.format(
                    "{\"header_name\":\"%s\",\"header_value\":\"%s\",\"replace_strategy\":\"%s\",\"priority\":%d,\"is_active\":true,\"ttl\":%d%s}",
                    JsonUtils.escapeJson(header[0]),
                    JsonUtils.escapeJson(header[1]),
                    strategy,
                    priority,
                    ttl,
                    scopeJson.equals("null") ? "" : ",\"scope\":" + scopeJson
                ));
            }
            headersArrayJson.append("]");
            
            String jsonPayload = "{\"headers\":" + headersArrayJson.toString() + "}";
            
            new Thread(() -> {
                try {
                    String response = apiClient.sendSessionHeaders(jsonPayload);
                    
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[+] 已提交 " + headers.size() + " 个会话Header");
                        uiTab.appendLog("    响应: " + response);
                    });
                    
                    api.logging().logToOutput("[+] Session headers submitted: " + headers.size() + " headers");
                    
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        uiTab.appendLog("[-] 提交会话Header失败: " + e.getMessage());
                    });
                    api.logging().logToError("[-] Error: " + e.getMessage());
                }
            }).start();
            
        } catch (Exception e) {
            uiTab.appendLog("[-] 构建JSON失败: " + e.getMessage());
            api.logging().logToError("[-] Error: " + e.getMessage());
        }
    }
}
