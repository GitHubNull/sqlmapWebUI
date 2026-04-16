package com.sqlmapwebui.burp.ui.dialog;

import com.sqlmapwebui.burp.config.ConfigManager;
import com.sqlmapwebui.burp.model.RegexSource;
import com.sqlmapwebui.burp.model.TitleRule;
import com.sqlmapwebui.burp.model.TitleSourceType;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 标题规则编辑对话框
 * 用于添加和编辑单条规则
 */
public class TitleRuleEditDialog extends JDialog {

    private final ConfigManager configManager;
    private TitleRule rule;
    private final boolean isDefaultRule;
    private boolean saved = false;
    
    // UI 组件
    private JTextField nameField;
    private JComboBox<TitleSourceType> typeComboBox;
    private JTextField fixedField;
    private JTextField pathSubStartField;
    private JTextField pathSubEndField;
    private JTextField regexField;
    private JSpinner regexGroupSpinner;
    private JComboBox<RegexSource> regexSourceComboBox;
    private JTextField jsonPathField;
    private JTextField xpathField;
    private JTextField formFieldField;
    private JTextArea remarkArea;
    private JCheckBox enabledCheckBox;
    
    // 参数面板
    private JPanel fixedPanel;
    private JPanel pathSubPanel;
    private JPanel regexPanel;
    private JPanel jsonPathPanel;
    private JPanel xpathPanel;
    private JPanel formFieldPanel;
    
    // 元数据标签
    private JLabel createdTimeLabel;
    private JLabel modifiedTimeLabel;
    
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    public TitleRuleEditDialog(Frame parent, ConfigManager configManager, TitleRule rule, boolean isDefaultRule) {
        super(parent, "编辑规则", true);
        this.configManager = configManager;
        this.rule = rule;
        this.isDefaultRule = isDefaultRule;
        
        initializeComponents();
        layoutComponents();
        loadRuleToUi();
        updateParameterPanels();
        
        setSize(500, 550);
        setLocationRelativeTo(parent);
    }
    
    private void initializeComponents() {
        nameField = new JTextField(25);
        
        // 类型下拉框
        typeComboBox = new JComboBox<>(TitleSourceType.values());
        typeComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof TitleSourceType) {
                    setText(getSourceTypeDisplayName((TitleSourceType) value));
                }
                return this;
            }
        });
        typeComboBox.addActionListener(e -> updateParameterPanels());
        
        // 固定值参数
        fixedField = new JTextField(25);
        fixedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fixedPanel.add(new JLabel("固定值:"));
        fixedPanel.add(fixedField);
        
        // 路径子串参数
        pathSubStartField = new JTextField(5);
        pathSubEndField = new JTextField(5);
        pathSubPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        pathSubPanel.add(new JLabel("起始:"));
        pathSubPanel.add(pathSubStartField);
        pathSubPanel.add(new JLabel("结束:"));
        pathSubPanel.add(pathSubEndField);
        
        // 正则参数
        regexField = new JTextField(20);
        regexGroupSpinner = new JSpinner(new SpinnerNumberModel(1, 0, 99, 1));
        regexSourceComboBox = new JComboBox<>(RegexSource.values());
        regexSourceComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof RegexSource) {
                    setText(getRegexSourceDisplayName((RegexSource) value));
                }
                return this;
            }
        });
        regexPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        regexPanel.add(new JLabel("表达式:"));
        regexPanel.add(regexField);
        regexPanel.add(new JLabel("捕获组:"));
        regexPanel.add(regexGroupSpinner);
        regexPanel.add(new JLabel("来源:"));
        regexPanel.add(regexSourceComboBox);
        
        // JSON Path 参数
        jsonPathField = new JTextField(25);
        jsonPathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jsonPathPanel.add(new JLabel("JSON Path:"));
        jsonPathPanel.add(jsonPathField);
        
        // XPath 参数
        xpathField = new JTextField(25);
        xpathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        xpathPanel.add(new JLabel("XPath:"));
        xpathPanel.add(xpathField);
        
        // 表单字段参数
        formFieldField = new JTextField(25);
        formFieldPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        formFieldPanel.add(new JLabel("字段名:"));
        formFieldPanel.add(formFieldField);
        
        // 备注
        remarkArea = new JTextArea(3, 25);
        remarkArea.setLineWrap(true);
        remarkArea.setWrapStyleWord(true);
        
        // 启用
        enabledCheckBox = new JCheckBox("启用此规则", true);
        if (isDefaultRule) {
            enabledCheckBox.setEnabled(false); // 默认规则始终启用
        }
        
        // 元数据
        createdTimeLabel = new JLabel();
        modifiedTimeLabel = new JLabel();
    }
    
    private void layoutComponents() {
        setLayout(new BorderLayout(10, 10));
        
        JPanel mainPanel = new JPanel(new BorderLayout(5, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 基本信息面板
        JPanel basicPanel = new JPanel(new GridBagLayout());
        basicPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "基本信息",
            TitledBorder.LEFT, TitledBorder.TOP));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0;
        basicPanel.add(new JLabel("规则名称:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        basicPanel.add(nameField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        basicPanel.add(new JLabel("提取类型:"), gbc);
        gbc.gridx = 1;
        basicPanel.add(typeComboBox, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        basicPanel.add(enabledCheckBox, gbc);
        
        mainPanel.add(basicPanel, BorderLayout.NORTH);
        
        // 参数面板（动态显示）
        JPanel paramsPanel = new JPanel(new CardLayout());
        paramsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "参数配置",
            TitledBorder.LEFT, TitledBorder.TOP));
        
        // URL_PATH 默认参数（子串）
        JPanel urlPathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        urlPathPanel.add(new JLabel("路径子串 - 起始:"));
        JTextField urlPathStart = new JTextField(5);
        urlPathPanel.add(urlPathStart);
        urlPathPanel.add(new JLabel("结束:"));
        JTextField urlPathEnd = new JTextField(5);
        urlPathPanel.add(urlPathEnd);
        // 添加占位面板
        paramsPanel.add(urlPathPanel, "URL_PATH");
        paramsPanel.add(fixedPanel, "FIXED");
        paramsPanel.add(pathSubPanel, "URL_PATH_SUB");
        paramsPanel.add(regexPanel, "REGEX");
        paramsPanel.add(jsonPathPanel, "JSON_PATH");
        paramsPanel.add(xpathPanel, "XPATH");
        paramsPanel.add(formFieldPanel, "FORM_FIELD");
        
        mainPanel.add(paramsPanel, BorderLayout.CENTER);
        
        // 底部面板
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
        
        // 备注面板
        JPanel remarkPanel = new JPanel(new BorderLayout(5, 5));
        remarkPanel.setBorder(BorderFactory.createTitledBorder("备注"));
        remarkPanel.add(new JScrollPane(remarkArea), BorderLayout.CENTER);
        bottomPanel.add(remarkPanel, BorderLayout.CENTER);
        
        // 元数据面板
        JPanel metaPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        metaPanel.add(new JLabel("创建时间:"));
        metaPanel.add(createdTimeLabel);
        metaPanel.add(new JLabel("修改时间:"));
        metaPanel.add(modifiedTimeLabel);
        bottomPanel.add(metaPanel, BorderLayout.SOUTH);
        
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("保存");
        saveBtn.addActionListener(e -> saveRule());
        JButton cancelBtn = new JButton("取消");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(saveBtn);
        buttonPanel.add(cancelBtn);
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    private void loadRuleToUi() {
        if (rule == null) return;
        
        nameField.setText(rule.getName());
        typeComboBox.setSelectedItem(rule.getSourceType());
        enabledCheckBox.setSelected(rule.isEnabled());
        fixedField.setText(rule.getFixedValue() != null ? rule.getFixedValue() : "");
        pathSubStartField.setText(rule.getPathSubStart() != null ? rule.getPathSubStart() : "0");
        pathSubEndField.setText(rule.getPathSubEnd() != null ? rule.getPathSubEnd() : "-0");
        regexField.setText(rule.getRegexPattern() != null ? rule.getRegexPattern() : "");
        regexGroupSpinner.setValue(rule.getRegexGroup());
        regexSourceComboBox.setSelectedItem(rule.getRegexSource());
        jsonPathField.setText(rule.getJsonPath() != null ? rule.getJsonPath() : "");
        xpathField.setText(rule.getXpath() != null ? rule.getXpath() : "");
        formFieldField.setText(rule.getFormField() != null ? rule.getFormField() : "");
        remarkArea.setText(rule.getRemark() != null ? rule.getRemark() : "");
        
        // 元数据
        if (rule.getCreatedTime() > 0) {
            createdTimeLabel.setText(DATE_FORMAT.format(new Date(rule.getCreatedTime())));
        }
        if (rule.getModifiedTime() > 0) {
            modifiedTimeLabel.setText(DATE_FORMAT.format(new Date(rule.getModifiedTime())));
        }
        
        // 默认规则特殊处理
        if (isDefaultRule) {
            nameField.setEnabled(false);
            typeComboBox.setEnabled(false);
        }
    }
    
    private void updateParameterPanels() {
        TitleSourceType selectedType = (TitleSourceType) typeComboBox.getSelectedItem();
        if (selectedType == null) return;
        
        // 获取父面板并切换显示
        Container parent = fixedPanel.getParent();
        if (parent instanceof JPanel) {
            CardLayout layout = (CardLayout) ((JPanel) parent).getLayout();
            layout.show((JPanel) parent, selectedType.name());
        }
    }
    
    private void saveRule() {
        // 验证名称
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "请输入规则名称", "验证失败", JOptionPane.WARNING_MESSAGE);
            nameField.requestFocus();
            return;
        }
        
        TitleSourceType type = (TitleSourceType) typeComboBox.getSelectedItem();
        if (type == null) {
            type = TitleSourceType.URL_PATH;
        }
        
        // 验证特定参数
        if (type == TitleSourceType.FIXED && fixedField.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "请输入固定值", "验证失败", JOptionPane.WARNING_MESSAGE);
            fixedField.requestFocus();
            return;
        }
        
        if (type == TitleSourceType.REGEX && regexField.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "请输入正则表达式", "验证失败", JOptionPane.WARNING_MESSAGE);
            regexField.requestFocus();
            return;
        }
        
        // 更新规则
        rule = new TitleRule(
            rule.getId(),
            name,
            type,
            enabledCheckBox.isSelected(),
            rule.getPriority(),
            fixedField.getText().trim(),
            pathSubStartField.getText().trim(),
            pathSubEndField.getText().trim(),
            regexField.getText().trim(),
            (Integer) regexGroupSpinner.getValue(),
            (RegexSource) regexSourceComboBox.getSelectedItem(),
            jsonPathField.getText().trim(),
            xpathField.getText().trim(),
            formFieldField.getText().trim(),
            rule.getCreatedTime(),
            System.currentTimeMillis(),
            remarkArea.getText().trim()
        );
        
        saved = true;
        dispose();
    }
    
    public boolean isSaved() {
        return saved;
    }
    
    public TitleRule getRule() {
        return rule;
    }
    
    private String getSourceTypeDisplayName(TitleSourceType type) {
        if (type == null) return "";
        switch (type) {
            case URL_PATH: return "URL路径";
            case URL_PATH_SUB: return "路径子串";
            case FIXED: return "固定值";
            case REGEX: return "正则表达式";
            case JSON_PATH: return "JSON Path";
            case XPATH: return "XPath";
            case FORM_FIELD: return "表单字段";
            default: return type.name();
        }
    }
    
    private String getRegexSourceDisplayName(RegexSource source) {
        if (source == null) return "";
        switch (source) {
            case URL: return "URL";
            case REQUEST_BODY: return "请求体";
            case FULL_REQUEST: return "完整请求";
            default: return source.name();
        }
    }
}
