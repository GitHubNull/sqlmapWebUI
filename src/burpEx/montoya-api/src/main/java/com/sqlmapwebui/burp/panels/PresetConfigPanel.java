package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.PresetConfig;
import com.sqlmapwebui.burp.PresetConfigDatabase;
import com.sqlmapwebui.burp.ScanConfigParser;
import com.sqlmapwebui.burp.SqlmapApiClient;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 常用配置面板
 * 使用SQLite存储，支持增删改查和高级搜索
 */
public class PresetConfigPanel extends BaseConfigPanel {
    
    private static final String[] COLUMN_NAMES = {"序号", "名称", "描述", "命令行参数", "创建时间", "最后修改时间"};
    
    private PresetConfigDatabase database;
    private ConfigImportExportHelper importExportHelper;
    private JTable configTable;
    private DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> rowSorter;
    private JLabel statusLabel;
    
    // 搜索组件
    private JTextField searchField;
    private JCheckBox regexCheckBox;
    private JCheckBox caseSensitiveCheckBox;
    private JCheckBox invertCheckBox;
    
    public PresetConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient, Consumer<String> logAppender) {
        super(configManager, apiClient, logAppender);
    }
    
    @Override
    protected void initializePanel() {
        // 初始化数据库
        database = new PresetConfigDatabase(this::appendLog);
        importExportHelper = new ConfigImportExportHelper(this, database, this::appendLog);
        
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 顶部工具栏
        add(createToolbar(), BorderLayout.NORTH);
        
        // 配置表格
        add(createTablePanel(), BorderLayout.CENTER);
        
        // 底部状态栏
        add(createStatusBar(), BorderLayout.SOUTH);
        
        // 加载数据
        refreshTable();
    }
    
    /**
     * 创建工具栏
     */
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout(10, 5));
        
        // 搜索面板
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        searchPanel.setBorder(BorderFactory.createTitledBorder("搜索过滤"));
        
        searchField = new JTextField(25);
        searchField.setToolTipText("输入关键字搜索（名称、描述、参数）");
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                applyFilter();
            }
        });
        searchPanel.add(new JLabel("关键字:"));
        searchPanel.add(searchField);
        
        // 高级搜索选项
        regexCheckBox = new JCheckBox("正则表达式");
        regexCheckBox.addActionListener(e -> applyFilter());
        searchPanel.add(regexCheckBox);
        
        caseSensitiveCheckBox = new JCheckBox("大小写敏感");
        caseSensitiveCheckBox.addActionListener(e -> applyFilter());
        searchPanel.add(caseSensitiveCheckBox);
        
        invertCheckBox = new JCheckBox("反选");
        invertCheckBox.addActionListener(e -> applyFilter());
        searchPanel.add(invertCheckBox);
        
        JButton clearSearchBtn = new JButton("清除");
        clearSearchBtn.addActionListener(e -> {
            searchField.setText("");
            regexCheckBox.setSelected(false);
            caseSensitiveCheckBox.setSelected(false);
            invertCheckBox.setSelected(false);
            applyFilter();
        });
        searchPanel.add(clearSearchBtn);
        
        toolbar.add(searchPanel, BorderLayout.CENTER);
        
        // 操作按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        
        JButton addBtn = new JButton("新增配置");
        addBtn.addActionListener(e -> showAddDialog());
        buttonPanel.add(addBtn);
        
        JButton guidedAddBtn = new JButton("引导式添加");
        guidedAddBtn.setToolTipText("通过引导式界面选择参数");
        guidedAddBtn.addActionListener(e -> showGuidedAddDialog());
        buttonPanel.add(guidedAddBtn);
        
        JButton editBtn = new JButton("编辑");
        editBtn.addActionListener(e -> showEditDialog());
        buttonPanel.add(editBtn);
        
        JButton guidedEditBtn = new JButton("引导式编辑");
        guidedEditBtn.setToolTipText("通过引导式界面编辑选中配置的参数");
        guidedEditBtn.addActionListener(e -> showGuidedEditDialog());
        buttonPanel.add(guidedEditBtn);
        
        JButton deleteBtn = new JButton("删除选中");
        deleteBtn.addActionListener(e -> deleteSelected());
        buttonPanel.add(deleteBtn);
        
        JButton refreshBtn = new JButton("刷新");
        refreshBtn.addActionListener(e -> refreshTable());
        buttonPanel.add(refreshBtn);
        
        // 分隔符
        buttonPanel.add(new JLabel(" | "));
        
        // 导入导出按钮
        JButton importBtn = new JButton("导入");
        importBtn.addActionListener(e -> {
            if (importExportHelper.showImportDialog() >= 0) {
                refreshTable();
            }
        });
        buttonPanel.add(importBtn);
        
        JButton exportBtn = new JButton("导出");
        exportBtn.addActionListener(e -> importExportHelper.showExportDialog());
        buttonPanel.add(exportBtn);
        
        toolbar.add(buttonPanel, BorderLayout.EAST);
        
        return toolbar;
    }
    
    /**
     * 创建表格面板
     */
    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("配置列表"));
        
        // 创建表格模型（不可编辑）
        tableModel = new DefaultTableModel(COLUMN_NAMES, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Long.class;
                }
                return String.class;
            }
        };
        
        configTable = new JTable(tableModel);
        configTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        configTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        configTable.setRowHeight(25);
        configTable.getTableHeader().setReorderingAllowed(false);
        
        // 设置行排序器
        configTable.setAutoCreateRowSorter(false);
        rowSorter = new TableRowSorter<>(tableModel);
        configTable.setRowSorter(rowSorter);
        
        // 设置列宽
        configTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        configTable.getColumnModel().getColumn(0).setMinWidth(40);
        configTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        configTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        configTable.getColumnModel().getColumn(3).setPreferredWidth(350);
        configTable.getColumnModel().getColumn(4).setPreferredWidth(150);
        configTable.getColumnModel().getColumn(5).setPreferredWidth(150);
        
        // 双击编辑
        configTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    showEditDialog();
                }
            }
        });
        
        // 右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem editMenuItem = new JMenuItem("编辑");
        editMenuItem.addActionListener(e -> showEditDialog());
        popupMenu.add(editMenuItem);
        
        JMenuItem guidedEditMenuItem = new JMenuItem("引导式编辑");
        guidedEditMenuItem.addActionListener(e -> showGuidedEditDialog());
        popupMenu.add(guidedEditMenuItem);
        
        popupMenu.addSeparator();
        
        JMenuItem deleteMenuItem = new JMenuItem("删除");
        deleteMenuItem.addActionListener(e -> deleteSelected());
        popupMenu.add(deleteMenuItem);
        
        popupMenu.addSeparator();
        
        JMenuItem copyMenuItem = new JMenuItem("复制参数字符串");
        copyMenuItem.addActionListener(e -> copyParameterString());
        popupMenu.add(copyMenuItem);
        
        configTable.setComponentPopupMenu(popupMenu);
        
        JScrollPane scrollPane = new JScrollPane(configTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建状态栏
     */
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("就绪");
        statusBar.add(statusLabel);
        return statusBar;
    }
    
    /**
     * 刷新表格数据
     */
    public void refreshTable() {
        tableModel.setRowCount(0);
        
        List<PresetConfig> configs = database.findAll();
        for (PresetConfig config : configs) {
            tableModel.addRow(new Object[]{
                config.getId(),
                config.getName(),
                config.getDescription(),
                config.getParameterString(),
                config.getFormattedCreatedTime(),
                config.getFormattedModifiedTime()
            });
        }
        
        updateStatus();
    }
    
    /**
     * 更新状态栏
     */
    private void updateStatus() {
        int total = tableModel.getRowCount();
        int visible = configTable.getRowCount();
        if (total == visible) {
            statusLabel.setText("共 " + total + " 条配置");
        } else {
            statusLabel.setText("显示 " + visible + " / " + total + " 条配置");
        }
    }
    
    /**
     * 应用搜索过滤
     */
    private void applyFilter() {
        String searchText = searchField.getText().trim();
        
        if (searchText.isEmpty()) {
            rowSorter.setRowFilter(null);
            updateStatus();
            return;
        }
        
        try {
            RowFilter<DefaultTableModel, Object> filter;
            
            if (regexCheckBox.isSelected()) {
                int flags = caseSensitiveCheckBox.isSelected() ? 0 : Pattern.CASE_INSENSITIVE;
                Pattern pattern = Pattern.compile(searchText, flags);
                
                filter = new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        for (int i = 1; i <= 3; i++) {
                            Object value = entry.getValue(i);
                            if (value != null && pattern.matcher(value.toString()).find()) {
                                return !invertCheckBox.isSelected();
                            }
                        }
                        return invertCheckBox.isSelected();
                    }
                };
            } else {
                String finalSearchText = caseSensitiveCheckBox.isSelected() ? searchText : searchText.toLowerCase();
                
                filter = new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        for (int i = 1; i <= 3; i++) {
                            Object value = entry.getValue(i);
                            if (value != null) {
                                String valueStr = caseSensitiveCheckBox.isSelected()
                                    ? value.toString() 
                                    : value.toString().toLowerCase();
                                if (valueStr.contains(finalSearchText)) {
                                    return !invertCheckBox.isSelected();
                                }
                            }
                        }
                        return invertCheckBox.isSelected();
                    }
                };
            }
            
            rowSorter.setRowFilter(filter);
            searchField.setBackground(Color.WHITE);
            
        } catch (PatternSyntaxException e) {
            searchField.setBackground(new Color(255, 200, 200));
        }
        
        updateStatus();
    }
    
    /**
     * 显示新增对话框
     */
    private void showAddDialog() {
        PresetConfigDialog dialog = new PresetConfigDialog(
            SwingUtilities.getWindowAncestor(this),
            "新增配置",
            null,
            database
        );
        dialog.setVisible(true);
        
        if (dialog.isConfirmed()) {
            PresetConfig config = dialog.getConfig();
            if (database.insert(config)) {
                refreshTable();
                appendLog("[+] 新增配置: " + config.getName());
            } else {
                HtmlMessageDialog.showError(this, "添加失败", 
                    "配置名称 <b>" + config.getName() + "</b> 已存在，请使用其他名称");
            }
        }
    }
    
    /**
     * 显示引导式添加对话框（一步完成名称、描述和参数配置）
     */
    private void showGuidedAddDialog() {
        Window window = SwingUtilities.getWindowAncestor(this);
        GuidedParamEditorDialog dialog = new GuidedParamEditorDialog(
            window, "引导式参数配置 - 新建", null, null, null);
        String paramString = dialog.showDialog();
        
        if (paramString != null) {
            String name = dialog.getResultName();
            String desc = dialog.getResultDescription();
            
            // 检查参数重复
            List<PresetConfig> allConfigs = database.findAll();
            List<String> duplicateNames = ScanConfigParser.findEquivalentConfigs(paramString, allConfigs);
            
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
            
            PresetConfig config = new PresetConfig();
            config.setName(name);
            config.setDescription(desc);
            config.setParameterString(paramString);
            
            if (database.insert(config)) {
                refreshTable();
                appendLog("[+] 引导式添加配置: " + name);
                HtmlMessageDialog.showInfo(this, "成功", "配置 <b>" + name + "</b> 已保存");
            } else {
                HtmlMessageDialog.showError(this, "添加失败", 
                    "配置名称 <b>" + name + "</b> 已存在，请使用其他名称");
            }
        }
    }
    
    /**
     * 显示保存为预设配置对话框
     */
    private void showSaveAsPresetDialog(String paramString) {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("配置名称:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JTextField nameField = new JTextField(20);
        panel.add(nameField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("描述:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JTextField descField = new JTextField(20);
        panel.add(descField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JPanel previewPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JLabel paramLabel = new JLabel("参数: ");
        paramLabel.setFont(paramLabel.getFont().deriveFont(Font.BOLD));
        previewPanel.add(paramLabel);
        
        String displayParam = paramString.length() > 50 ? paramString.substring(0, 50) + "..." : paramString;
        JLabel paramValueLabel = new JLabel(displayParam);
        paramValueLabel.setForeground(Color.GRAY);
        previewPanel.add(paramValueLabel);
        panel.add(previewPanel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        JCheckBox ignoreDuplicateCheckBox = new JCheckBox("无视参数重复");
        ignoreDuplicateCheckBox.setToolTipText("勾选后将不检查命令行参数是否与现有配置重复");
        panel.add(ignoreDuplicateCheckBox, gbc);
        
        int result = JOptionPane.showConfirmDialog(this, panel, "保存配置",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        
        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String desc = descField.getText().trim();
            
            if (name.isEmpty()) {
                HtmlMessageDialog.showWarning(this, "警告", "配置名称不能为空");
                return;
            }
            
            if (!ignoreDuplicateCheckBox.isSelected()) {
                List<PresetConfig> allConfigs = database.findAll();
                List<String> duplicateNames = ScanConfigParser.findEquivalentConfigs(paramString, allConfigs);
                
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
            
            PresetConfig config = new PresetConfig();
            config.setName(name);
            config.setDescription(desc);
            config.setParameterString(paramString);
            
            if (database.insert(config)) {
                refreshTable();
                appendLog("[+] 引导式添加配置: " + name);
                HtmlMessageDialog.showInfo(this, "成功", "配置 <b>" + name + "</b> 已保存");
            } else {
                HtmlMessageDialog.showError(this, "添加失败", 
                    "配置名称 <b>" + name + "</b> 已存在，请使用其他名称");
            }
        }
    }
    
    /**
     * 显示编辑对话框
     */
    private void showEditDialog() {
        int selectedRow = configTable.getSelectedRow();
        if (selectedRow < 0) {
            HtmlMessageDialog.showWarning(this, "提示", "请先选择要编辑的配置");
            return;
        }
        
        int modelRow = configTable.convertRowIndexToModel(selectedRow);
        long id = (Long) tableModel.getValueAt(modelRow, 0);
        
        PresetConfig config = database.findById(id);
        if (config == null) {
            HtmlMessageDialog.showError(this, "错误", "配置不存在");
            return;
        }
        
        PresetConfigDialog dialog = new PresetConfigDialog(
            SwingUtilities.getWindowAncestor(this),
            "编辑配置",
            config,
            database
        );
        dialog.setVisible(true);
        
        if (dialog.isConfirmed()) {
            PresetConfig updatedConfig = dialog.getConfig();
            if (database.update(updatedConfig)) {
                refreshTable();
                appendLog("[+] 更新配置: " + updatedConfig.getName());
            } else {
                HtmlMessageDialog.showError(this, "更新失败", 
                    "配置名称 <b>" + updatedConfig.getName() + "</b> 已被其他配置使用，请使用其他名称");
            }
        }
    }
    
    /**
     * 显示引导式编辑对话框（一步完成名称、描述和参数配置）
     */
    private void showGuidedEditDialog() {
        int selectedRow = configTable.getSelectedRow();
        if (selectedRow < 0) {
            HtmlMessageDialog.showWarning(this, "提示", "请先选择要编辑的配置");
            return;
        }
        
        int modelRow = configTable.convertRowIndexToModel(selectedRow);
        long id = (Long) tableModel.getValueAt(modelRow, 0);
        
        PresetConfig config = database.findById(id);
        if (config == null) {
            HtmlMessageDialog.showError(this, "错误", "配置不存在");
            return;
        }
        
        Window window = SwingUtilities.getWindowAncestor(this);
        GuidedParamEditorDialog dialog = new GuidedParamEditorDialog(
            window, "引导式参数配置 - 编辑", 
            config.getParameterString(), config.getName(), config.getDescription());
        String newParamString = dialog.showDialog();
        
        if (newParamString != null) {
            String newName = dialog.getResultName();
            String newDesc = dialog.getResultDescription();
            
            config.setName(newName);
            config.setDescription(newDesc);
            config.setParameterString(newParamString);
            
            if (database.update(config)) {
                refreshTable();
                appendLog("[+] 引导式更新配置: " + newName);
                HtmlMessageDialog.showInfo(this, "成功", "配置 <b>" + newName + "</b> 已更新");
            } else {
                HtmlMessageDialog.showError(this, "更新失败", 
                    "配置名称 <b>" + newName + "</b> 已被其他配置使用，请使用其他名称");
            }
        }
    }
    
    /**
     * 删除选中的配置
     */
    private void deleteSelected() {
        int[] selectedRows = configTable.getSelectedRows();
        if (selectedRows.length == 0) {
            HtmlMessageDialog.showWarning(this, "提示", "请先选择要删除的配置");
            return;
        }
        
        boolean confirm = HtmlMessageDialog.showConfirm(this, "确认删除",
            "<p>确定要删除选中的 <b>" + selectedRows.length + "</b> 条配置吗？</p>" +
            "<p style='color: red;'>此操作不可恢复！</p>");
        
        if (!confirm) {
            return;
        }
        
        List<Long> idsToDelete = new ArrayList<>();
        for (int viewRow : selectedRows) {
            int modelRow = configTable.convertRowIndexToModel(viewRow);
            long id = (Long) tableModel.getValueAt(modelRow, 0);
            idsToDelete.add(id);
        }
        
        int deleted = database.deleteByIds(idsToDelete);
        if (deleted > 0) {
            refreshTable();
            appendLog("[+] 已删除 " + deleted + " 条配置");
            HtmlMessageDialog.showInfo(this, "删除成功", 
                "已成功删除 <b>" + deleted + "</b> 条配置");
        }
    }
    
    /**
     * 复制参数字符串到剪贴板
     */
    private void copyParameterString() {
        int selectedRow = configTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        int modelRow = configTable.convertRowIndexToModel(selectedRow);
        String paramString = (String) tableModel.getValueAt(modelRow, 3);
        
        if (paramString != null && !paramString.isEmpty()) {
            java.awt.datatransfer.StringSelection selection = 
                new java.awt.datatransfer.StringSelection(paramString);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            appendLog("[+] 已复制参数字符串到剪贴板");
        }
    }
    
    /**
     * 获取数据库实例
     */
    public PresetConfigDatabase getDatabase() {
        return database;
    }
}
