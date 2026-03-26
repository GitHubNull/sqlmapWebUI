package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.util.TitleRule;
import com.sqlmapwebui.burp.dialogs.TitleRuleEditDialog;
import com.sqlmapwebui.burp.dialogs.TitleTestDialog;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * 标题提取规则配置面板
 * 以表格形式展示和管理规则列表
 */
public class TitleRulesPanel extends JPanel {

    private final ConfigManager configManager;
    private final JTable rulesTable;
    private final RulesTableModel tableModel;
    
    // 工具栏按钮
    private JButton addBtn;
    private JButton editBtn;
    private JButton deleteBtn;
    private JButton moveUpBtn;
    private JButton moveDownBtn;
    private JButton testBtn;
    
    // 全局配置
    private JTextField fallbackField;
    private JSpinner maxLengthSpinner;
    
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm");
    
    public TitleRulesPanel(ConfigManager configManager) {
        this.configManager = configManager;
        this.tableModel = new RulesTableModel();
        this.rulesTable = new JTable(tableModel);
        
        initializeComponents();
        layoutComponents();
        loadRules();
    }
    
    private void initializeComponents() {
        // 设置表格属性
        rulesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        rulesTable.setRowHeight(28);
        rulesTable.getTableHeader().setReorderingAllowed(false);
        
        // 设置列宽
        TableColumnModel columnModel = rulesTable.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(40);   // 启用
        columnModel.getColumn(1).setPreferredWidth(120);  // 名称
        columnModel.getColumn(2).setPreferredWidth(80);   // 类型
        columnModel.getColumn(3).setPreferredWidth(120);  // 参数
        columnModel.getColumn(4).setPreferredWidth(50);   // 优先级
        columnModel.getColumn(5).setPreferredWidth(150);  // 备注
        
        // 渲染器
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        rulesTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        
        // 选择监听
        rulesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateButtonStates();
            }
        });
        
        // 双击编辑
        rulesTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = rulesTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        editRule();
                    }
                }
            }
        });
        
        // 按钮
        addBtn = new JButton("添加规则");
        addBtn.addActionListener(e -> addRule());
        
        editBtn = new JButton("编辑规则");
        editBtn.addActionListener(e -> editRule());
        
        deleteBtn = new JButton("删除规则");
        deleteBtn.addActionListener(e -> deleteRule());
        
        moveUpBtn = new JButton("上移");
        moveUpBtn.addActionListener(e -> moveRuleUp());
        
        moveDownBtn = new JButton("下移");
        moveDownBtn.addActionListener(e -> moveRuleDown());
        
        testBtn = new JButton("测试提取");
        testBtn.addActionListener(e -> testRules());
        
        // 全局配置
        fallbackField = new JTextField(15);
        fallbackField.setText(configManager.getTitleFallback());
        
        maxLengthSpinner = new JSpinner(new SpinnerNumberModel(
            configManager.getTitleMaxLength(), 10, 200, 5));
    }
    
    private void layoutComponents() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "终端窗口标题规则配置",
            javax.swing.border.TitledBorder.LEFT,
            javax.swing.border.TitledBorder.TOP
        ));
        
        // 顶部：全局配置
        JPanel globalPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        globalPanel.add(new JLabel("全局回退标题:"));
        globalPanel.add(fallbackField);
        globalPanel.add(new JLabel("最大长度:"));
        globalPanel.add(maxLengthSpinner);
        add(globalPanel, BorderLayout.NORTH);
        
        // 中间：规则表
        JScrollPane scrollPane = new JScrollPane(rulesTable);
        scrollPane.setPreferredSize(new Dimension(600, 200));
        add(scrollPane, BorderLayout.CENTER);
        
        // 底部：工具栏
        JPanel toolbarPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        toolbarPanel.add(addBtn);
        toolbarPanel.add(editBtn);
        toolbarPanel.add(deleteBtn);
        toolbarPanel.add(new JSeparator(SwingConstants.VERTICAL));
        toolbarPanel.add(moveUpBtn);
        toolbarPanel.add(moveDownBtn);
        toolbarPanel.add(new JSeparator(SwingConstants.VERTICAL));
        toolbarPanel.add(testBtn);
        add(toolbarPanel, BorderLayout.SOUTH);
        
        updateButtonStates();
    }
    
    public void loadRules() {
        List<TitleRule> rules = configManager.getTitleRules();
        tableModel.setRules(rules);
        fallbackField.setText(configManager.getTitleFallback());
        maxLengthSpinner.setValue(configManager.getTitleMaxLength());
    }
    
    public void saveRules() {
        // 保存规则列表
        configManager.setTitleRules(tableModel.getRules());
        
        // 保存全局配置
        configManager.setTitleFallback(fallbackField.getText().trim());
        configManager.setTitleMaxLength((Integer) maxLengthSpinner.getValue());
    }
    
    /**
     * 保存配置（供外部调用）
     */
    public void saveConfiguration() {
        saveRules();
    }
    
    /**
     * 获取当前规则列表
     */
    public List<TitleRule> getCurrentRules() {
        return tableModel.getRules();
    }
    
    /**
     * 获取当前回退标题
     */
    public String getCurrentFallback() {
        return fallbackField.getText().trim();
    }
    
    /**
     * 获取当前标题最大长度
     */
    public int getCurrentMaxLength() {
        return (Integer) maxLengthSpinner.getValue();
    }
    
    /**
     * 重置为默认配置
     */
    public void resetToDefault() {
        // 重置全局配置
        fallbackField.setText("SQLMap");
        maxLengthSpinner.setValue(50);
        
        // 重置规则列表为默认
        List<TitleRule> defaultRules = new ArrayList<>();
        defaultRules.add(TitleRule.createDefaultRule());
        configManager.setTitleRules(defaultRules);
        
        loadRules();
    }
    
    /**
     * 显示测试对话框
     */
    public void showTestDialog() {
        testRules();
    }
    
    private void addRule() {
        TitleRule newRule = new TitleRule();
        newRule.setName("新规则");
        newRule.setSourceType(com.sqlmapwebui.burp.util.TitleSourceType.URL_PATH);
        newRule.setEnabled(true);
        
        TitleRuleEditDialog dialog = new TitleRuleEditDialog(
            (Frame) SwingUtilities.getWindowAncestor(this), configManager, newRule, false);
        dialog.setVisible(true);
        
        if (dialog.isSaved()) {
            configManager.addTitleRule(dialog.getRule());
            loadRules();
        }
    }
    
    private void editRule() {
        int selectedRow = rulesTable.getSelectedRow();
        if (selectedRow < 0) return;
        
        TitleRule rule = tableModel.getRuleAt(selectedRow);
        if (rule == null) return;
        
        // 创建副本进行编辑
        TitleRule editRule = new TitleRule(
            rule.getId(), rule.getName(), rule.getSourceType(), rule.isEnabled(),
            rule.getPriority(), rule.getFixedValue(), rule.getPathSubStart(), rule.getPathSubEnd(),
            rule.getRegexPattern(), rule.getRegexGroup(), rule.getRegexSource(),
            rule.getJsonPath(), rule.getXpath(), rule.getFormField(),
            rule.getCreatedTime(), rule.getModifiedTime(), rule.getRemark()
        );
        
        boolean isDefault = rule.isDefaultRule();
        TitleRuleEditDialog dialog = new TitleRuleEditDialog(
            (Frame) SwingUtilities.getWindowAncestor(this), configManager, editRule, isDefault);
        dialog.setVisible(true);
        
        if (dialog.isSaved()) {
            configManager.updateTitleRule(dialog.getRule());
            loadRules();
        }
    }
    
    private void deleteRule() {
        int selectedRow = rulesTable.getSelectedRow();
        if (selectedRow < 0) return;
        
        TitleRule rule = tableModel.getRuleAt(selectedRow);
        if (rule == null) return;
        
        if (rule.isDefaultRule()) {
            JOptionPane.showMessageDialog(this,
                "默认规则不可删除",
                "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int confirm = JOptionPane.showConfirmDialog(this,
            "确定要删除规则 \"" + rule.getName() + "\" 吗？",
            "确认删除", JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            configManager.deleteTitleRule(rule.getId());
            loadRules();
        }
    }
    
    private void moveRuleUp() {
        int selectedRow = rulesTable.getSelectedRow();
        if (selectedRow < 0) return;
        
        TitleRule rule = tableModel.getRuleAt(selectedRow);
        if (rule == null || rule.isDefaultRule()) return;
        
        configManager.moveRuleUp(rule.getId());
        loadRules();
        
        // 重新选中
        int newRow = Math.max(1, selectedRow - 1);
        rulesTable.setRowSelectionInterval(newRow, newRow);
    }
    
    private void moveRuleDown() {
        int selectedRow = rulesTable.getSelectedRow();
        if (selectedRow < 0) return;
        
        TitleRule rule = tableModel.getRuleAt(selectedRow);
        if (rule == null || rule.isDefaultRule()) return;
        
        configManager.moveRuleDown(rule.getId());
        loadRules();
        
        // 重新选中
        int newRow = Math.min(tableModel.getRowCount() - 1, selectedRow + 1);
        rulesTable.setRowSelectionInterval(newRow, newRow);
    }
    
    private void testRules() {
        TitleTestDialog dialog = new TitleTestDialog(configManager, null);
        dialog.setVisible(true);
    }
    
    private void updateButtonStates() {
        int selectedRow = rulesTable.getSelectedRow();
        boolean hasSelection = selectedRow >= 0;
        boolean isDefault = hasSelection && tableModel.getRuleAt(selectedRow) != null
            && tableModel.getRuleAt(selectedRow).isDefaultRule();
        
        editBtn.setEnabled(hasSelection);
        deleteBtn.setEnabled(hasSelection && !isDefault);
        moveUpBtn.setEnabled(hasSelection && !isDefault && selectedRow > 1);
        moveDownBtn.setEnabled(hasSelection && !isDefault && selectedRow < tableModel.getRowCount() - 1);
    }
    
    /**
     * 规则表格模型
     */
    private class RulesTableModel extends AbstractTableModel {
        
        private final String[] COLUMN_NAMES = {"启用", "规则名称", "类型", "参数预览", "优先级", "备注"};
        private List<TitleRule> rules = new ArrayList<>();
        
        public void setRules(List<TitleRule> rules) {
            this.rules = new ArrayList<>(rules);
            fireTableDataChanged();
        }
        
        public List<TitleRule> getRules() {
            return new ArrayList<>(rules);
        }
        
        public TitleRule getRuleAt(int rowIndex) {
            if (rowIndex >= 0 && rowIndex < rules.size()) {
                return rules.get(rowIndex);
            }
            return null;
        }
        
        @Override
        public int getRowCount() {
            return rules.size();
        }
        
        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TitleRule rule = rules.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return rule.isEnabled();
                case 1:
                    return rule.getName();
                case 2:
                    return getSourceTypeDisplayName(rule.getSourceType());
                case 3:
                    return rule.getParamPreview();
                case 4:
                    return rule.getPriority();
                case 5:
                    return rule.getRemark();
                default:
                    return null;
            }
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) {
                return Boolean.class;
            } else if (columnIndex == 4) {
                return Integer.class;
            }
            return String.class;
        }
        
        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            // 只有启用列可编辑
            return columnIndex == 0;
        }
        
        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && aValue instanceof Boolean) {
                TitleRule rule = rules.get(rowIndex);
                rule.setEnabled((Boolean) aValue);
                rule.touch();
                configManager.updateTitleRule(rule);
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
        
        private String getSourceTypeDisplayName(com.sqlmapwebui.burp.util.TitleSourceType type) {
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
    }
}
