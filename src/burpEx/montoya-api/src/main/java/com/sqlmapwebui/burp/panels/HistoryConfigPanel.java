package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.ScanConfig;
import com.sqlmapwebui.burp.SqlmapApiClient;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 历史配置面板
 * 管理扫描历史记录，支持搜索、过滤、多选删除
 */
public class HistoryConfigPanel extends BaseConfigPanel {
    
    private JTable historyConfigTable;
    private DefaultTableModel historyTableModel;
    private TableRowSorter<DefaultTableModel> historySorter;
    private JTextField historySearchField;
    private JCheckBox regexCheckBox;
    private JCheckBox caseSensitiveCheckBox;
    private JCheckBox invertCheckBox;
    private JLabel historyStatusLabel;
    
    public HistoryConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient, Consumer<String> logAppender) {
        super(configManager, apiClient, logAppender);
    }
    
    @Override
    protected void initializePanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 搜索面板
        JPanel searchPanel = new JPanel(new BorderLayout(5, 5));
        searchPanel.setBorder(BorderFactory.createTitledBorder("搜索过滤"));
        
        // 搜索输入行
        JPanel searchInputPanel = new JPanel(new BorderLayout(5, 0));
        searchInputPanel.add(new JLabel("搜索:"), BorderLayout.WEST);
        historySearchField = new JTextField(30);
        historySearchField.setToolTipText("输入关键词过滤历史记录");
        searchInputPanel.add(historySearchField, BorderLayout.CENTER);
        
        JButton searchButton = new JButton("搜索");
        searchButton.addActionListener(e -> applyHistoryFilter());
        searchInputPanel.add(searchButton, BorderLayout.EAST);
        
        // 快捷键支持
        historySearchField.addActionListener(e -> applyHistoryFilter());
        
        searchPanel.add(searchInputPanel, BorderLayout.NORTH);
        
        // 高级搜索选项
        JPanel advancedOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        advancedOptionsPanel.add(new JLabel("高级选项:"));
        
        regexCheckBox = new JCheckBox("正则表达式");
        regexCheckBox.setToolTipText("使用正则表达式进行匹配");
        advancedOptionsPanel.add(regexCheckBox);
        
        caseSensitiveCheckBox = new JCheckBox("大小写敏感");
        caseSensitiveCheckBox.setToolTipText("区分大小写进行匹配");
        advancedOptionsPanel.add(caseSensitiveCheckBox);
        
        invertCheckBox = new JCheckBox("反选");
        invertCheckBox.setToolTipText("显示不匹配的结果");
        advancedOptionsPanel.add(invertCheckBox);
        
        advancedOptionsPanel.add(Box.createHorizontalStrut(20));
        
        JButton clearSearchBtn = new JButton("清除过滤");
        clearSearchBtn.addActionListener(e -> {
            historySearchField.setText("");
            applyHistoryFilter();
        });
        advancedOptionsPanel.add(clearSearchBtn);
        
        searchPanel.add(advancedOptionsPanel, BorderLayout.CENTER);
        add(searchPanel, BorderLayout.NORTH);
        
        // 历史记录表格
        String[] historyColumns = {"序号", "参数(s)字符串", "日期时间"};
        historyTableModel = new DefaultTableModel(historyColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) return Integer.class;
                return String.class;
            }
        };
        
        historyConfigTable = new JTable(historyTableModel);
        historyConfigTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        historyConfigTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        
        // 设置列宽度
        historyConfigTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        historyConfigTable.getColumnModel().getColumn(0).setMinWidth(40);
        historyConfigTable.getColumnModel().getColumn(1).setPreferredWidth(500);
        historyConfigTable.getColumnModel().getColumn(2).setPreferredWidth(160);
        historyConfigTable.getColumnModel().getColumn(2).setMinWidth(160);
        
        // 设置排序器
        historySorter = new TableRowSorter<>(historyTableModel);
        historyConfigTable.setRowSorter(historySorter);
        
        // 先初始化状态标签（refreshHistoryTable会用到）
        historyStatusLabel = new JLabel("共 0 条记录");
        
        // 刷新表格数据
        refreshHistoryTable();
        
        JScrollPane scrollPane = new JScrollPane(historyConfigTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("历史扫描配置记录"));
        add(scrollPane, BorderLayout.CENTER);
        
        // 操作按钮面板
        JPanel buttonPanel = new JPanel(new BorderLayout());
        
        // 左侧按钮
        JPanel leftButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton selectAllBtn = new JButton("全选");
        selectAllBtn.addActionListener(e -> historyConfigTable.selectAll());
        leftButtonPanel.add(selectAllBtn);
        
        JButton deselectAllBtn = new JButton("取消全选");
        deselectAllBtn.addActionListener(e -> historyConfigTable.clearSelection());
        leftButtonPanel.add(deselectAllBtn);
        
        JButton invertSelectionBtn = new JButton("反选");
        invertSelectionBtn.addActionListener(e -> invertTableSelection());
        leftButtonPanel.add(invertSelectionBtn);
        
        buttonPanel.add(leftButtonPanel, BorderLayout.WEST);
        
        // 右侧按钮
        JPanel rightButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton deleteSelectedBtn = new JButton("删除选中");
        deleteSelectedBtn.addActionListener(e -> deleteSelectedHistory());
        rightButtonPanel.add(deleteSelectedBtn);
        
        JButton clearAllBtn = new JButton("清空全部");
        clearAllBtn.addActionListener(e -> clearAllHistory());
        rightButtonPanel.add(clearAllBtn);
        
        JButton refreshBtn = new JButton("刷新");
        refreshBtn.addActionListener(e -> refreshHistoryTable());
        rightButtonPanel.add(refreshBtn);
        
        buttonPanel.add(rightButtonPanel, BorderLayout.EAST);
        
        // 状态栏
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.add(historyStatusLabel);
        buttonPanel.add(statusPanel, BorderLayout.CENTER);
        
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    private void applyHistoryFilter() {
        String searchText = historySearchField.getText().trim();
        boolean isRegex = regexCheckBox.isSelected();
        boolean caseSensitive = caseSensitiveCheckBox.isSelected();
        boolean invert = invertCheckBox.isSelected();
        
        if (searchText.isEmpty()) {
            historySorter.setRowFilter(null);
            updateHistoryStatus();
            return;
        }
        
        try {
            RowFilter<DefaultTableModel, Object> filter;
            
            if (isRegex) {
                // 正则表达式模式
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                Pattern pattern = Pattern.compile(searchText, flags);
                filter = new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        String value = entry.getStringValue(1);
                        boolean matches = pattern.matcher(value).find();
                        return invert ? !matches : matches;
                    }
                };
            } else {
                // 普通字符串模式
                final String search = caseSensitive ? searchText : searchText.toLowerCase();
                filter = new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        String value = entry.getStringValue(1);
                        if (!caseSensitive) value = value.toLowerCase();
                        boolean matches = value.contains(search);
                        return invert ? !matches : matches;
                    }
                };
            }
            
            historySorter.setRowFilter(filter);
            updateHistoryStatus();
            
        } catch (PatternSyntaxException e) {
            JOptionPane.showMessageDialog(this, 
                "无效的正则表达式: " + e.getMessage(), 
                "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void updateHistoryStatus() {
        int total = historyTableModel.getRowCount();
        int visible = historyConfigTable.getRowCount();
        int selected = historyConfigTable.getSelectedRowCount();
        
        if (total != visible) {
            historyStatusLabel.setText(String.format("显示 %d/%d 条记录，已选中 %d 条", visible, total, selected));
        } else {
            historyStatusLabel.setText(String.format("共 %d 条记录，已选中 %d 条", total, selected));
        }
    }
    
    private void invertTableSelection() {
        int rowCount = historyConfigTable.getRowCount();
        ListSelectionModel selectionModel = historyConfigTable.getSelectionModel();
        
        boolean[] currentSelection = new boolean[rowCount];
        for (int i = 0; i < rowCount; i++) {
            currentSelection[i] = selectionModel.isSelectedIndex(i);
        }
        
        selectionModel.clearSelection();
        for (int i = 0; i < rowCount; i++) {
            if (!currentSelection[i]) {
                selectionModel.addSelectionInterval(i, i);
            }
        }
        updateHistoryStatus();
    }
    
    public void refreshHistoryTable() {
        historyTableModel.setRowCount(0);
        List<ScanConfig> historyConfigs = configManager.getHistoryConfigs();
        
        int index = 1;
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        
        for (ScanConfig config : historyConfigs) {
            String paramString = config.toCommandLineString();
            if (paramString.isEmpty()) {
                paramString = "(默认参数)";
            }
            String dateTime = sdf.format(new java.util.Date(config.getLastUsedAt()));
            
            historyTableModel.addRow(new Object[]{
                index++,
                paramString,
                dateTime
            });
        }
        
        updateHistoryStatus();
    }
    
    private void deleteSelectedHistory() {
        int[] selectedViewRows = historyConfigTable.getSelectedRows();
        if (selectedViewRows.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选择要删除的记录", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int confirm = JOptionPane.showConfirmDialog(this,
            "确定要删除选中的 " + selectedViewRows.length + " 条记录吗?",
            "确认删除", JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            int[] modelRows = new int[selectedViewRows.length];
            for (int i = 0; i < selectedViewRows.length; i++) {
                modelRows[i] = historyConfigTable.convertRowIndexToModel(selectedViewRows[i]);
            }
            
            java.util.Arrays.sort(modelRows);
            
            configManager.removeHistoryByIndices(modelRows);
            refreshHistoryTable();
            appendLog("[+] 已删除 " + selectedViewRows.length + " 条历史记录");
        }
    }
    
    private void clearAllHistory() {
        if (configManager.getHistorySize() == 0) {
            JOptionPane.showMessageDialog(this, "历史记录已为空", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        int confirm = JOptionPane.showConfirmDialog(this,
            "确定要清空所有历史记录吗?",
            "确认清空", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        
        if (confirm == JOptionPane.YES_OPTION) {
            configManager.clearHistory();
            refreshHistoryTable();
            appendLog("[+] 已清空所有历史记录");
        }
    }
}
