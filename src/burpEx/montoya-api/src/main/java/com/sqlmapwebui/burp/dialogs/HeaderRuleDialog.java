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
 * Header规则对话框
 */
public class HeaderRuleDialog {
    
    private final MontoyaApi api;
    private final SqlmapApiClient apiClient;
    private final SqlmapUITab uiTab;
    
    public HeaderRuleDialog(MontoyaApi api, SqlmapApiClient apiClient, SqlmapUITab uiTab) {
        this.api = api;
        this.apiClient = apiClient;
        this.uiTab = uiTab;
    }
    
    /**
     * 显示Header规则配置对话框
     */
    public void show(HttpRequest request) {
        JDialog dialog = new JDialog((Frame) null, "提交Header规则", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(900, 750);
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
            "<b>选择要提交为持久化规则的Header字段</b><br>" +
            "持久化规则将永久保存，并应用于所有匹配的请求<br>" +
            "<span style='color:gray;'>提示: 每个规则需要一个唯一的名称来标识</span>" +
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
            tableData[i] = new Object[]{false, headerName, headerValue};
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
        tableButtonPanel.add(selectAllBtn);
        tableButtonPanel.add(deselectAllBtn);
        headerSelectionPanel.add(tableButtonPanel, BorderLayout.SOUTH);
        
        contentPanel.add(headerSelectionPanel, BorderLayout.CENTER);
        
        // 规则配置面板
        JPanel ruleConfigPanel = createRuleConfigPanel(request);
        contentPanel.add(ruleConfigPanel, BorderLayout.SOUTH);
        dialog.add(contentPanel, BorderLayout.CENTER);
        
        // 从ruleConfigPanel提取组件引用
        JTextField namePrefixField = findComponentByName(ruleConfigPanel, "namePrefixField", JTextField.class);
        JComboBox<?> strategyCombo = findComponentByName(ruleConfigPanel, "strategyCombo", JComboBox.class);
        JSpinner prioritySpinner = findComponentByName(ruleConfigPanel, "prioritySpinner", JSpinner.class);
        JCheckBox isActiveCheck = findComponentByName(ruleConfigPanel, "isActiveCheck", JCheckBox.class);
        JCheckBox enableScopeCheck = findComponentByName(ruleConfigPanel, "enableScopeCheck", JCheckBox.class);
        JComboBox<?> protocolCombo = findComponentByName(ruleConfigPanel, "protocolCombo", JComboBox.class);
        JTextField hostField = findComponentByName(ruleConfigPanel, "hostField", JTextField.class);
        JTextField pathField = findComponentByName(ruleConfigPanel, "pathField", JTextField.class);
        JCheckBox useRegexCheck = findComponentByName(ruleConfigPanel, "useRegexCheck", JCheckBox.class);
        
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
            
            String namePrefix = namePrefixField.getText().trim();
            if (namePrefix.isEmpty()) {
                namePrefix = "Rule_";
            }
            
            String scopeJson = "null";
            if (enableScopeCheck.isSelected()) {
                String protocol = (String) protocolCombo.getSelectedItem();
                String host = hostField.getText().trim();
                String path = pathField.getText().trim();
                boolean useRegex = useRegexCheck.isSelected();
                
                scopeJson = String.format(
                    "{\"protocol_pattern\":\"%s\",\"host_pattern\":\"%s\",\"path_pattern\":\"%s\",\"use_regex\":%s}",
                    JsonUtils.escapeJson(protocol), JsonUtils.escapeJson(host), JsonUtils.escapeJson(path), useRegex
                );
            }
            
            String strategy = (String) strategyCombo.getSelectedItem();
            int priority = (Integer) prioritySpinner.getValue();
            boolean isActive = isActiveCheck.isSelected();
            
            sendHeaderRulesToBackend(selectedHeaders, namePrefix, scopeJson, strategy, priority, isActive);
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
     * 创建规则配置面板
     */
    private JPanel createRuleConfigPanel(HttpRequest request) {
        JPanel ruleConfigPanel = new JPanel(new GridBagLayout());
        ruleConfigPanel.setBorder(BorderFactory.createTitledBorder("规则配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // 规则名称前缀
        JLabel namePrefixLabel = new JLabel("规则名称前缀:");
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1; gbc.weightx = 0;
        ruleConfigPanel.add(namePrefixLabel, gbc);
        JTextField namePrefixField = new JTextField("Rule_");
        namePrefixField.setName("namePrefixField");
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(namePrefixField, gbc);
        
        // 替换策略
        JLabel strategyLabel = new JLabel("替换策略:");
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        ruleConfigPanel.add(strategyLabel, gbc);
        JComboBox<String> strategyCombo = new JComboBox<>(new String[]{"REPLACE", "APPEND", "PREPEND", "UPSERT", "CONDITIONAL"});
        strategyCombo.setName("strategyCombo");
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(strategyCombo, gbc);
        
        // 优先级
        JLabel priorityLabel = new JLabel("优先级(0-100):");
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        ruleConfigPanel.add(priorityLabel, gbc);
        JSpinner prioritySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 100, 1));
        prioritySpinner.setName("prioritySpinner");
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(prioritySpinner, gbc);
        
        // 是否启用
        JCheckBox isActiveCheck = new JCheckBox("立即启用规则", true);
        isActiveCheck.setName("isActiveCheck");
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        ruleConfigPanel.add(isActiveCheck, gbc);
        
        // 作用域配置
        JCheckBox enableScopeCheck = new JCheckBox("启用作用域限制");
        enableScopeCheck.setName("enableScopeCheck");
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        ruleConfigPanel.add(enableScopeCheck, gbc);
        
        String hostFromRequest = "";
        try {
            java.net.URL urlObj = new java.net.URL(request.url());
            hostFromRequest = urlObj.getHost();
        } catch (Exception e) {
            hostFromRequest = "";
        }
        
        JLabel protocolLabel = new JLabel("协议:");
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1; gbc.weightx = 0;
        ruleConfigPanel.add(protocolLabel, gbc);
        JComboBox<String> protocolCombo = new JComboBox<>(new String[]{"", "http", "https"});
        protocolCombo.setName("protocolCombo");
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(protocolCombo, gbc);
        
        JLabel hostLabel = new JLabel("主机名模式:");
        gbc.gridx = 0; gbc.gridy = 6; gbc.weightx = 0;
        ruleConfigPanel.add(hostLabel, gbc);
        JTextField hostField = new JTextField(hostFromRequest);
        hostField.setName("hostField");
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(hostField, gbc);
        
        JLabel pathLabel = new JLabel("路径模式:");
        gbc.gridx = 0; gbc.gridy = 7; gbc.weightx = 0;
        ruleConfigPanel.add(pathLabel, gbc);
        JTextField pathField = new JTextField();
        pathField.setName("pathField");
        gbc.gridx = 1; gbc.weightx = 1;
        ruleConfigPanel.add(pathField, gbc);
        
        JCheckBox useRegexCheck = new JCheckBox("使用正则表达式");
        useRegexCheck.setName("useRegexCheck");
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 2;
        ruleConfigPanel.add(useRegexCheck, gbc);
        
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
        
        return ruleConfigPanel;
    }
    
    /**
     * 根据名称和类型安全地查找组件
     * @param container 容器
     * @param name 组件名称
     * @param type 期望的组件类型
     * @return 找到的组件，如果未找到或类型不匹配则返回null
     */
    private <T extends Component> T findComponentByName(Container container, String name, Class<T> type) {
        for (Component c : container.getComponents()) {
            if (name.equals(c.getName()) && type.isInstance(c)) {
                return type.cast(c);
            }
            if (c instanceof Container) {
                T result = findComponentByName((Container) c, name, type);
                if (result != null) return result;
            }
        }
        return null;
    }
    
    /**
     * 发送Header规则到后端
     */
    private void sendHeaderRulesToBackend(List<String[]> headers, String namePrefix,
                                          String scopeJson, String strategy, int priority, boolean isActive) {
        for (int i = 0; i < headers.size(); i++) {
            String[] header = headers.get(i);
            String ruleName = namePrefix + header[0];
            
            try {
                StringBuilder jsonBuilder = new StringBuilder("{");
                jsonBuilder.append(String.format("\"name\":\"%s\",", JsonUtils.escapeJson(ruleName)));
                jsonBuilder.append(String.format("\"header_name\":\"%s\",", JsonUtils.escapeJson(header[0])));
                jsonBuilder.append(String.format("\"header_value\":\"%s\",", JsonUtils.escapeJson(header[1])));
                jsonBuilder.append(String.format("\"replace_strategy\":\"%s\",", strategy));
                jsonBuilder.append(String.format("\"priority\":%d,", priority));
                jsonBuilder.append(String.format("\"is_active\":%s", isActive));
                if (!scopeJson.equals("null")) {
                    jsonBuilder.append(",\"scope\":" + scopeJson);
                }
                jsonBuilder.append("}");
                
                String jsonPayload = jsonBuilder.toString();
                
                final String finalRuleName = ruleName;
                final int index = i;
                final int total = headers.size();
                
                new Thread(() -> {
                    try {
                        String response = apiClient.sendHeaderRule(jsonPayload);
                        
                        SwingUtilities.invokeLater(() -> {
                            uiTab.appendLog("[+] 已提交Header规则 (" + (index + 1) + "/" + total + "): " + finalRuleName);
                            uiTab.appendLog("    响应: " + response);
                        });
                        
                        api.logging().logToOutput("[+] Header rule submitted: " + finalRuleName);
                        
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            uiTab.appendLog("[-] 提交Header规则失败: " + finalRuleName + " - " + e.getMessage());
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
}
