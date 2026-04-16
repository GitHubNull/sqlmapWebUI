package com.sqlmapwebui.burp.ui.dialog;

import com.sqlmapwebui.burp.config.PresetConfig;
import com.sqlmapwebui.burp.config.PresetConfigDatabase;
import com.sqlmapwebui.burp.config.ScanConfigParser;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;

/**
 * 预设配置编辑对话框
 */
public class PresetConfigDialog extends JDialog {
    
    private final PresetConfigDatabase database;
    private PresetConfig config;
    private boolean confirmed = false;
    
    private JTextField nameField;
    private JTextArea descriptionArea;
    private JTextArea parameterArea;
    private JCheckBox ignoreDuplicateCheckBox;
    
    public PresetConfigDialog(Window owner, String title, PresetConfig config, PresetConfigDatabase database) {
        super(owner, title, ModalityType.APPLICATION_MODAL);
        this.database = database;
        this.config = config != null ? config : new PresetConfig();
        
        initializeDialog();
        loadData();
    }
    
    private void initializeDialog() {
        setLayout(new BorderLayout(10, 10));
        setSize(650, 620);
        setLocationRelativeTo(getOwner());
        setResizable(true);
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 10, 15));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        
        // 名称
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("名称 *:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        nameField = new JTextField(30);
        nameField.setToolTipText("配置名称（必填，唯一）");
        formPanel.add(nameField, gbc);
        
        // 描述
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("描述:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 0.3;
        descriptionArea = new JTextArea(3, 30);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setToolTipText("配置描述（可选）");
        formPanel.add(new JScrollPane(descriptionArea), gbc);
        
        // 参数字符串
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0; gbc.weighty = 0;
        JPanel paramLabelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        paramLabelPanel.add(new JLabel("命令行参数 *:"));
        JButton guidedEditBtn = new JButton("引导式编辑");
        guidedEditBtn.setFont(new Font("Microsoft YaHei", Font.PLAIN, 11));
        guidedEditBtn.setMargin(new Insets(2, 8, 2, 8));
        guidedEditBtn.setToolTipText("打开引导式参数编辑器，可视化编辑现有参数或添加新参数");
        guidedEditBtn.addActionListener(e -> openGuidedParamEditor());
        paramLabelPanel.add(Box.createHorizontalStrut(10));
        paramLabelPanel.add(guidedEditBtn);
        formPanel.add(paramLabelPanel, gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 0.7;
        parameterArea = new JTextArea(6, 30);
        parameterArea.setLineWrap(true);
        parameterArea.setWrapStyleWord(true);
        parameterArea.setToolTipText("SQLMap命令行参数，如: --level=5 --risk=3 --batch");
        formPanel.add(new JScrollPane(parameterArea), gbc);
        
        // 无视重复复选框
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE; gbc.weighty = 0;
        ignoreDuplicateCheckBox = new JCheckBox("无视参数重复（不检查命令行参数是否与其他配置等效）");
        ignoreDuplicateCheckBox.setToolTipText("勾选后将不检查命令行参数是否与现有配置重复");
        formPanel.add(ignoreDuplicateCheckBox, gbc);
        
        // 帮助说明面板
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; 
        gbc.fill = GridBagConstraints.BOTH; gbc.weighty = 0.3;
        JEditorPane helpPane = new JEditorPane();
        helpPane.setContentType("text/html");
        helpPane.setEditable(false);
        helpPane.setOpaque(false);
        helpPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        helpPane.setFont(new Font("Microsoft YaHei", Font.PLAIN, 11));
        helpPane.setText(
            "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', sans-serif; font-size: 11px; margin: 5px; }" +
            "h4 { margin: 5px 0 3px 0; color: #2c3e50; }" +
            "ul { margin: 2px 0 5px 15px; padding: 0; }" +
            "li { margin: 1px 0; }" +
            ".code { font-family: Consolas, monospace; background: #ecf0f1; padding: 1px 3px; }" +
            "</style></head><body>" +
            "<h4>📝 参数说明</h4>" +
            "<ul>" +
            "<li><span class='code'>--level=N</span> 检测级别 (1-5)，默认1</li>" +
            "<li><span class='code'>--risk=N</span> 风险级别 (1-3)，默认1</li>" +
            "<li><span class='code'>--technique=BEUSTQ</span> 注入技术，B=布尔型, E=报错, U=联合, S=堆叠, T=时间盲注, Q=内联</li>" +
            "<li><span class='code'>--batch</span> 批处理模式，不询问用户</li>" +
            "<li><span class='code'>--threads=N</span> 并发线程数 (1-10)</li>" +
            "<li><span class='code'>--proxy=URL</span> 代理服务器，如 http://127.0.0.1:8080</li>" +
            "<li><span class='code'>--tamper=SCRIPT</span> 绕过脚本，如 space2comment</li>" +
            "</ul>" +
            "<p style='color: gray;'>示例: <span class='code'>--level=5 --risk=3 --technique=BEUSTQ --batch --threads=5</span></p>" +
            "</body></html>"
        );
        JScrollPane helpScrollPane = new JScrollPane(helpPane);
        helpScrollPane.setPreferredSize(new Dimension(500, 120));
        helpScrollPane.setBorder(BorderFactory.createTitledBorder("帮助说明"));
        formPanel.add(helpScrollPane, gbc);
        
        add(formPanel, BorderLayout.CENTER);
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        
        JButton saveBtn = new JButton("保存");
        saveBtn.addActionListener(e -> save());
        buttonPanel.add(saveBtn);
        
        JButton cancelBtn = new JButton("取消");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(cancelBtn);
        
        add(buttonPanel, BorderLayout.SOUTH);
        
        // 设置默认按钮
        getRootPane().setDefaultButton(saveBtn);
        
        // ESC关闭
        getRootPane().registerKeyboardAction(
            e -> dispose(),
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
            JComponent.WHEN_IN_FOCUSED_WINDOW
        );
    }
    
    private void loadData() {
        if (config.getId() > 0) {
            nameField.setText(config.getName());
            descriptionArea.setText(config.getDescription());
            parameterArea.setText(config.getParameterString());
        }
    }
    
    /**
     * 打开引导式参数编辑器
     */
    private void openGuidedParamEditor() {
        String currentParams = parameterArea.getText().trim();
        String result = GuidedParamEditorDialog.showEditParamDialog(this, currentParams);
        
        if (result != null) {
            parameterArea.setText(result);
            parameterArea.setCaretPosition(0);
        }
    }
    
    private void save() {
        String name = nameField.getText().trim();
        String description = descriptionArea.getText().trim();
        String parameters = parameterArea.getText().trim();
        
        // 验证
        if (name.isEmpty()) {
            HtmlMessageDialog.showWarning(this, "验证失败", "名称不能为空");
            nameField.requestFocus();
            return;
        }
        
        if (parameters.isEmpty()) {
            HtmlMessageDialog.showWarning(this, "验证失败", "参数字符串不能为空");
            parameterArea.requestFocus();
            return;
        }
        
        // 检查名称是否重复
        Long excludeId = config.getId() > 0 ? config.getId() : null;
        if (database.existsByName(name, excludeId)) {
            HtmlMessageDialog.showWarning(this, "验证失败", 
                "名称「" + name + "」已存在，请使用其他名称");
            nameField.requestFocus();
            return;
        }
        
        // 检查参数字符串是否重复（如果没有勾选"无视重复"）
        if (!ignoreDuplicateCheckBox.isSelected()) {
            List<PresetConfig> allConfigs = database.findAll();
            List<String> duplicateNames;
            
            if (config.getId() > 0) {
                // 编辑模式：排除自己
                duplicateNames = ScanConfigParser.findEquivalentConfigsExcludeId(parameters, allConfigs, config.getId());
            } else {
                // 新增模式
                duplicateNames = ScanConfigParser.findEquivalentConfigs(parameters, allConfigs);
            }
            
            if (!duplicateNames.isEmpty()) {
                String duplicateList = String.join(", ", duplicateNames);
                boolean proceed = HtmlMessageDialog.showConfirm(this, "参数重复确认",
                    "<p>当前参数与以下配置的参数效果等效：</p>" +
                    "<p style='color: #e74c3c; font-weight: bold;'>" + duplicateList + "</p>" +
                    "<p>是否仍然继续保存？</p>");
                
                if (!proceed) {
                    return;
                }
            }
        }
        
        config.setName(name);
        config.setDescription(description);
        config.setParameterString(parameters);
        
        confirmed = true;
        dispose();
    }
    
    public boolean isConfirmed() {
        return confirmed;
    }
    
    public PresetConfig getConfig() {
        return config;
    }
}
