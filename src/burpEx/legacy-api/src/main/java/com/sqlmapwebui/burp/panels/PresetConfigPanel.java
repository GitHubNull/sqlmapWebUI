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
import java.io.*;
import java.nio.charset.StandardCharsets;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

/**
 * 常用配置面板
 * 使用SQLite存储，支持增删改查和高级搜索
 */
public class PresetConfigPanel extends BaseConfigPanel {
    
    private static final String[] COLUMN_NAMES = {"序号", "名称", "描述", "命令行参数", "创建时间", "最后修改时间"};
    
    private PresetConfigDatabase database;
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
        importBtn.addActionListener(e -> showImportDialog());
        buttonPanel.add(importBtn);
        
        JButton exportBtn = new JButton("导出");
        exportBtn.addActionListener(e -> showExportDialog());
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
                    return Long.class; // 序号列用Long类型以正确排序
                }
                return String.class;
            }
        };
        
        configTable = new JTable(tableModel);
        configTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        configTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        configTable.setRowHeight(25);
        configTable.getTableHeader().setReorderingAllowed(false);
        
        // 启用表头点击排序
        configTable.setAutoCreateRowSorter(false);  // 使用自定义rowSorter
        
        // 设置行排序器
        rowSorter = new TableRowSorter<>(tableModel);
        configTable.setRowSorter(rowSorter);
        
        // 设置列宽
        configTable.getColumnModel().getColumn(0).setPreferredWidth(50);   // 序号
        configTable.getColumnModel().getColumn(0).setMinWidth(40);
        configTable.getColumnModel().getColumn(1).setPreferredWidth(120);  // 名称
        configTable.getColumnModel().getColumn(1).setMinWidth(80);
        configTable.getColumnModel().getColumn(2).setPreferredWidth(150);  // 描述
        configTable.getColumnModel().getColumn(2).setMinWidth(100);
        configTable.getColumnModel().getColumn(3).setPreferredWidth(400);  // 命令行参数
        configTable.getColumnModel().getColumn(3).setMinWidth(200);
        configTable.getColumnModel().getColumn(4).setPreferredWidth(150);  // 创建时间
        configTable.getColumnModel().getColumn(4).setMinWidth(130);
        configTable.getColumnModel().getColumn(5).setPreferredWidth(150);  // 最后修改时间
        configTable.getColumnModel().getColumn(5).setMinWidth(130);
        
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
        JPopupMenu popupMenu = createPopupMenu();
        configTable.setComponentPopupMenu(popupMenu);
        
        JScrollPane scrollPane = new JScrollPane(configTable);
        scrollPane.setPreferredSize(new Dimension(900, 400));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建右键菜单
     */
    private JPopupMenu createPopupMenu() {
        JPopupMenu menu = new JPopupMenu();
        
        JMenuItem editItem = new JMenuItem("编辑");
        editItem.addActionListener(e -> showEditDialog());
        menu.add(editItem);
        
        JMenuItem guidedEditItem = new JMenuItem("引导式编辑");
        guidedEditItem.addActionListener(e -> showGuidedEditDialog());
        menu.add(guidedEditItem);
        
        JMenuItem copyItem = new JMenuItem("复制参数");
        copyItem.addActionListener(e -> copyParameterString());
        menu.add(copyItem);
        
        menu.addSeparator();
        
        JMenuItem deleteItem = new JMenuItem("删除");
        deleteItem.addActionListener(e -> deleteSelected());
        menu.add(deleteItem);
        
        return menu;
    }
    
    /**
     * 创建状态栏
     */
    private JPanel createStatusBar() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("共 0 条配置");
        panel.add(statusLabel);
        return panel;
    }
    
    /**
     * 刷新表格数据
     */
    public void refreshTable() {
        tableModel.setRowCount(0);
        
        List<PresetConfig> configs = database.findAll();
        int index = 1;
        for (PresetConfig config : configs) {
            tableModel.addRow(new Object[]{
                config.getId(),
                config.getName(),
                config.getDescription(),
                config.getParameterString(),
                config.getFormattedCreatedTime(),
                config.getFormattedModifiedTime()
            });
            index++;
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
            statusLabel.setText("显示 " + visible + " / 共 " + total + " 条配置");
        }
    }
    
    /**
     * 应用过滤器
     */
    private void applyFilter() {
        String text = searchField.getText().trim();
        
        if (text.isEmpty()) {
            rowSorter.setRowFilter(null);
            updateStatus();
            return;
        }
        
        try {
            RowFilter<DefaultTableModel, Object> filter;
            
            if (regexCheckBox.isSelected()) {
                // 正则表达式模式
                int flags = caseSensitiveCheckBox.isSelected() ? 0 : Pattern.CASE_INSENSITIVE;
                Pattern pattern = Pattern.compile(text, flags);
                
                filter = new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ?> entry) {
                        // 搜索名称、描述、参数字符串（列1, 2, 3）
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
                // 普通文本模式
                String searchText = caseSensitiveCheckBox.isSelected() ? text : text.toLowerCase();
                
                filter = new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ?> entry) {
                        for (int i = 1; i <= 3; i++) {
                            Object value = entry.getValue(i);
                            if (value != null) {
                                String valueStr = caseSensitiveCheckBox.isSelected() 
                                    ? value.toString() 
                                    : value.toString().toLowerCase();
                                if (valueStr.contains(searchText)) {
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
     * 显示引导式添加对话框
     */
    private void showGuidedAddDialog() {
        String paramString = GuidedParamEditorDialog.showNewParamDialog(this);
        if (paramString != null && !paramString.trim().isEmpty()) {
            // 显示名称和描述输入对话框
            showSaveAsPresetDialog(paramString);
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
        
        // 使用组合组件避免HTML渲染问题
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
        
        // 无视重复复选框
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
            
            // 检查参数字符串是否重复（如果没有勾选“无视重复”）
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
        
        // 转换为模型索引
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
     * 显示引导式编辑对话框
     */
    private void showGuidedEditDialog() {
        int selectedRow = configTable.getSelectedRow();
        if (selectedRow < 0) {
            HtmlMessageDialog.showWarning(this, "提示", "请先选择要编辑的配置");
            return;
        }
        
        // 转换为模型索引
        int modelRow = configTable.convertRowIndexToModel(selectedRow);
        long id = (Long) tableModel.getValueAt(modelRow, 0);
        
        PresetConfig config = database.findById(id);
        if (config == null) {
            HtmlMessageDialog.showError(this, "错误", "配置不存在");
            return;
        }
        
        // 显示引导式编辑器（带当前参数）
        String newParamString = GuidedParamEditorDialog.showEditParamDialog(this, config.getParameterString());
        
        if (newParamString != null) {
            // 更新配置
            config.setParameterString(newParamString);
            if (database.update(config)) {
                refreshTable();
                appendLog("[+] 引导式更新配置: " + config.getName());
                HtmlMessageDialog.showInfo(this, "成功", "配置 <b>" + config.getName() + "</b> 已更新");
            } else {
                HtmlMessageDialog.showError(this, "更新失败", 
                    "配置名称 <b>" + config.getName() + "</b> 已被其他配置使用，请使用其他名称");
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
        
        // 收集要删除的ID（从模型索引获取）
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
    
    // ========== 导入导出功能 ==========
    
    /**
     * 显示导入对话框
     */
    private void showImportDialog() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入配置");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
            "YAML/SQL 文件 (*.yaml, *.yml, *.sql)", "yaml", "yml", "sql"));
        fileChooser.setAcceptAllFileFilterUsed(false);
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            String fileName = file.getName().toLowerCase();
            
            try {
                int imported = 0;
                if (fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
                    imported = importFromYaml(file);
                } else if (fileName.endsWith(".sql")) {
                    imported = importFromSql(file);
                } else {
                    HtmlMessageDialog.showWarning(this, "不支持的格式", 
                        "请选择 .yaml, .yml 或 .sql 文件");
                    return;
                }
                
                refreshTable();
                appendLog("[+] 导入完成，成功导入 " + imported + " 条配置");
                HtmlMessageDialog.showInfo(this, "导入成功", 
                    "成功导入 <b>" + imported + "</b> 条配置");
                    
            } catch (Exception e) {
                appendLog("[-] 导入失败: " + e.getMessage());
                HtmlMessageDialog.showError(this, "导入失败", e.getMessage());
            }
        }
    }
    
    /**
     * 显示导出对话框
     */
    private void showExportDialog() {
        List<PresetConfig> configs = database.findAll();
        if (configs.isEmpty()) {
            HtmlMessageDialog.showWarning(this, "无数据", "没有可导出的配置数据");
            return;
        }
        
        // 选择导出格式
        String[] options = {"YAML 格式", "SQL 格式", "取消"};
        int choice = JOptionPane.showOptionDialog(this,
            "请选择导出格式",
            "导出配置",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]);
        
        if (choice == 2 || choice == JOptionPane.CLOSED_OPTION) {
            return;
        }
        
        String extension = (choice == 0) ? "yaml" : "sql";
        String description = (choice == 0) ? "YAML 文件 (*.yaml)" : "SQL 文件 (*.sql)";
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出配置");
        fileChooser.setSelectedFile(new File("preset_configs." + extension));
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
            description, extension));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            
            // 确保文件后缀正确
            if (!file.getName().toLowerCase().endsWith("." + extension)) {
                file = new File(file.getAbsolutePath() + "." + extension);
            }
            
            try {
                if (choice == 0) {
                    exportToYaml(file, configs);
                } else {
                    exportToSql(file, configs);
                }
                
                appendLog("[+] 导出完成: " + file.getAbsolutePath());
                HtmlMessageDialog.showInfo(this, "导出成功", 
                    "<p>已导出 <b>" + configs.size() + "</b> 条配置</p>" +
                    "<p>文件: " + file.getName() + "</p>");
                    
            } catch (Exception e) {
                appendLog("[-] 导出失败: " + e.getMessage());
                HtmlMessageDialog.showError(this, "导出失败", e.getMessage());
            }
        }
    }
    
    /**
     * 从YAML文件导入
     */
    @SuppressWarnings("unchecked")
    private int importFromYaml(File file) throws Exception {
        Yaml yaml = new Yaml();
        int count = 0;
        
        try (FileInputStream fis = new FileInputStream(file);
             InputStreamReader reader = new InputStreamReader(fis, StandardCharsets.UTF_8)) {
            
            Object data = yaml.load(reader);
            
            if (data instanceof List) {
                List<java.util.Map<String, Object>> configs = (List<java.util.Map<String, Object>>) data;
                
                for (java.util.Map<String, Object> configMap : configs) {
                    String name = String.valueOf(configMap.getOrDefault("name", ""));
                    String description = String.valueOf(configMap.getOrDefault("description", ""));
                    String parameters = String.valueOf(configMap.getOrDefault("parameters", ""));
                    
                    if (!name.isEmpty() && !parameters.isEmpty()) {
                        // 检查名称是否已存在，如果存在则跳过
                        if (!database.existsByName(name, null)) {
                            PresetConfig config = new PresetConfig(name, description, parameters);
                            if (database.insert(config)) {
                                count++;
                            }
                        }
                    }
                }
            }
        }
        
        return count;
    }
    
    // 允许的SQL操作类型（白名单）
    private static final String[] ALLOWED_SQL_OPERATIONS = {"INSERT", "CREATE TABLE"};
    
    /**
     * 从SQL文件导入（安全模式：仅支持CREATE TABLE和INSERT）
     */
    private int importFromSql(File file) throws Exception {
        int count = 0;
        List<String> statements = new ArrayList<>();
        
        // 第一步：读取并验证所有SQL语句
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            
            String line;
            StringBuilder sb = new StringBuilder();
            int lineNumber = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                
                // 跳过注释和空行
                if (line.isEmpty() || line.startsWith("--") || line.startsWith("/*")) {
                    continue;
                }
                
                sb.append(line).append(" ");
                
                // 处理完整的SQL语句
                if (line.endsWith(";")) {
                    String sql = sb.toString().trim();
                    sb.setLength(0);
                    
                    // 安全检查：验证SQL操作类型
                    if (!isAllowedSqlOperation(sql)) {
                        String operation = extractSqlOperation(sql);
                        throw new SecurityException(
                            "安全错误：检测到不允许的SQL操作\n" +
                            "行号: " + lineNumber + "\n" +
                            "操作类型: " + operation + "\n" +
                            "仅允许: CREATE TABLE, INSERT\n\n" +
                            "导入已终止，未做任何修改。");
                    }
                    
                    statements.add(sql);
                }
            }
        }
        
        // 第二步：所有语句验证通过后，才执行INSERT操作
        for (String sql : statements) {
            if (sql.toUpperCase().startsWith("INSERT")) {
                PresetConfig config = parseInsertSql(sql);
                if (config != null && !database.existsByName(config.getName(), null)) {
                    if (database.insert(config)) {
                        count++;
                    }
                }
            }
            // CREATE TABLE 语句跳过（不执行，仅允许存在）
        }
        
        return count;
    }
    
    /**
     * 检查SQL操作是否在白名单中
     */
    private boolean isAllowedSqlOperation(String sql) {
        String upperSql = sql.toUpperCase().trim();
        for (String allowed : ALLOWED_SQL_OPERATIONS) {
            if (upperSql.startsWith(allowed)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 提取SQL操作类型
     */
    private String extractSqlOperation(String sql) {
        String upperSql = sql.toUpperCase().trim();
        // 提取第一个单词或前两个单词
        String[] parts = upperSql.split("\\s+");
        if (parts.length >= 2 && (parts[0].equals("CREATE") || parts[0].equals("DROP") || parts[0].equals("ALTER"))) {
            return parts[0] + " " + parts[1];
        }
        return parts.length > 0 ? parts[0] : "UNKNOWN";
    }
    
    /**
     * 解析INSERT SQL语句
     */
    private PresetConfig parseInsertSql(String sql) {
        try {
            // 简化解析: INSERT INTO preset_configs (name, description, parameter_string) VALUES ('...', '...', '...');
            int valuesStart = sql.toUpperCase().indexOf("VALUES");
            if (valuesStart < 0) return null;
            
            String valuesPart = sql.substring(valuesStart + 6).trim();
            // 移除括号和分号
            valuesPart = valuesPart.replaceAll("^\\(", "").replaceAll("\\);?$", "");
            
            // 解析单引号包围的值
            List<String> values = new ArrayList<>();
            StringBuilder current = new StringBuilder();
            boolean inQuote = false;
            boolean escaped = false;
            
            for (char c : valuesPart.toCharArray()) {
                if (escaped) {
                    current.append(c);
                    escaped = false;
                } else if (c == '\\' || (c == '\'' && inQuote)) {
                    if (c == '\\') {
                        escaped = true;
                    } else {
                        // 检查是否是转义的单引号
                        inQuote = !inQuote;
                        if (!inQuote) {
                            values.add(current.toString());
                            current.setLength(0);
                        }
                    }
                } else if (c == '\'' && !inQuote) {
                    inQuote = true;
                } else if (inQuote) {
                    current.append(c);
                }
            }
            
            if (values.size() >= 3) {
                String name = values.get(0).replace("''", "'");
                String description = values.get(1).replace("''", "'");
                String parameters = values.get(2).replace("''", "'");
                return new PresetConfig(name, description, parameters);
            }
        } catch (Exception e) {
            appendLog("[-] SQL解析失败: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * 导出到YAML文件
     */
    private void exportToYaml(File file, List<PresetConfig> configs) throws Exception {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setIndent(2);
        options.setAllowUnicode(true);
        
        Yaml yaml = new Yaml(options);
        
        List<java.util.Map<String, Object>> dataList = new ArrayList<>();
        for (PresetConfig config : configs) {
            java.util.Map<String, Object> map = new java.util.LinkedHashMap<>();
            map.put("name", config.getName());
            map.put("description", config.getDescription());
            map.put("parameters", config.getParameterString());
            map.put("created_time", config.getFormattedCreatedTime());
            map.put("modified_time", config.getFormattedModifiedTime());
            dataList.add(map);
        }
        
        try (FileOutputStream fos = new FileOutputStream(file);
             OutputStreamWriter writer = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
            writer.write("# SQLMap WebUI 常用配置导出\n");
            writer.write("# 导出时间: " + java.time.LocalDateTime.now().format(PresetConfig.DATE_FORMATTER) + "\n\n");
            yaml.dump(dataList, writer);
        }
    }
    
    /**
     * 导出到SQL文件
     */
    private void exportToSql(File file, List<PresetConfig> configs) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(file);
             OutputStreamWriter writer = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
            
            writer.write("-- SQLMap WebUI 常用配置导出\n");
            writer.write("-- 导出时间: " + java.time.LocalDateTime.now().format(PresetConfig.DATE_FORMATTER) + "\n");
            writer.write("-- 数据条数: " + configs.size() + "\n\n");
            
            writer.write("-- 建表语句 (可选)\n");
            writer.write("CREATE TABLE IF NOT EXISTS preset_configs (\n");
            writer.write("    id INTEGER PRIMARY KEY AUTOINCREMENT,\n");
            writer.write("    name TEXT NOT NULL,\n");
            writer.write("    description TEXT,\n");
            writer.write("    parameter_string TEXT NOT NULL,\n");
            writer.write("    created_time TEXT NOT NULL,\n");
            writer.write("    modified_time TEXT NOT NULL\n");
            writer.write(");\n\n");
            
            writer.write("-- 数据\n");
            for (PresetConfig config : configs) {
                writer.write(String.format(
                    "INSERT INTO preset_configs (name, description, parameter_string, created_time, modified_time) VALUES ('%s', '%s', '%s', '%s', '%s');\n",
                    escapeSql(config.getName()),
                    escapeSql(config.getDescription()),
                    escapeSql(config.getParameterString()),
                    config.getFormattedCreatedTime(),
                    config.getFormattedModifiedTime()
                ));
            }
        }
    }
    
    /**
     * 转义SQL字符串
     */
    private String escapeSql(String value) {
        if (value == null) return "";
        return value.replace("'", "''");
    }
    
    // ========== 内部类：配置编辑对话框 ==========
    
    private static class PresetConfigDialog extends JDialog {
        
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
            formPanel.add(new JLabel("参数字符串 *:"), gbc);
            
            gbc.gridx = 1; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 0.7;
            parameterArea = new JTextArea(6, 30);
            parameterArea.setLineWrap(true);
            parameterArea.setWrapStyleWord(true);
            parameterArea.setToolTipText("SQLMap参数字符串，如: --level=5 --risk=3 --batch");
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
            
            // 检查参数字符串是否重复（如果没有勾选“无视重复”）
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
}
