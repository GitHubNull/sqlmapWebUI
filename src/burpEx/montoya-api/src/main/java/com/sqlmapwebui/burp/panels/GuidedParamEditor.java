package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ParamMeta;
import com.sqlmapwebui.burp.ScanConfig;
import com.sqlmapwebui.burp.ScanConfigParser;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 引导式参数编辑器组件
 * 可复用的扫描参数配置组件，支持：
 * 1. 参数搜索（正则匹配、大小写敏感、反转）
 * 2. 根据参数类型动态显示输入控件
 * 3. 实时命令行预览（HTML高亮）
 * 4. 可嵌入面板或作为对话框使用
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class GuidedParamEditor extends JPanel {
    
    // ==================== 常量定义 ====================
    
    /** 参数分类 */
    private static final String[] PARAM_CATEGORIES = {
        "全部", "Detection 检测", "Injection 注入", "Techniques 技术",
        "Request 请求", "Optimization 优化", "Enumeration 枚举", "General 通用"
    };
    
    /** 参数分类映射 */
    private static final Map<String, List<String>> CATEGORY_PARAMS = new LinkedHashMap<>();
    
    /** DBMS 选项 */
    private static final String[] DBMS_OPTIONS = {
        "", "MySQL", "Oracle", "PostgreSQL", "Microsoft SQL Server", "SQLite",
        "Microsoft Access", "Firebird", "Sybase", "SAP MaxDB", "IBM DB2",
        "HSQLDB", "H2", "Informix", "MonetDB", "Apache Derby"
    };
    
    /** OS 选项 */
    private static final String[] OS_OPTIONS = {"", "Linux", "Windows"};
    
    /** HTTP 方法选项 */
    private static final String[] METHOD_OPTIONS = {
        "", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    };
    
    static {
        initCategoryParams();
    }
    
    // ==================== UI 组件 ====================
    
    // 搜索面板
    private JTextField searchField;
    private JCheckBox regexCheckBox;
    private JCheckBox caseSensitiveCheckBox;
    private JCheckBox invertCheckBox;
    private JComboBox<String> categoryCombo;
    
    // 参数列表
    private JList<ParamListItem> paramList;
    private DefaultListModel<ParamListItem> paramListModel;
    
    // 参数输入面板
    private JPanel inputPanel;
    private JPanel paramLabelPanel;
    private JLabel paramNameLabel;
    private JLabel paramDescLabel;
    private JPanel dynamicInputPanel;
    private JButton addParamButton;
    private JButton removeParamButton;
    
    // 已选参数面板
    private JList<SelectedParam> selectedParamList;
    private DefaultListModel<SelectedParam> selectedParamModel;
    
    // 命令行预览
    private JEditorPane commandPreviewPane;
    
    // 数据
    private final Map<String, Object> selectedParams = new LinkedHashMap<>();
    private ParamListItem currentSelectedParam = null;
    private JComponent currentInputComponent = null;
    
    // 回调
    private Runnable onChangeCallback;
    
    // ==================== 构造函数 ====================
    
    public GuidedParamEditor() {
        initializePanel();
    }
    
    /**
     * 带初始参数字符串的构造函数
     */
    public GuidedParamEditor(String initialParams) {
        initializePanel();
        if (initialParams != null && !initialParams.trim().isEmpty()) {
            loadFromParamString(initialParams);
        }
    }
    
    // ==================== 初始化 ====================
    
    private void initializePanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 左侧：参数搜索和列表
        JPanel leftPanel = createParamSearchPanel();
        
        // 中间：参数输入和已选列表
        JPanel centerPanel = createParamInputPanel();
        
        // 下方：命令行预览
        JPanel previewPanel = createPreviewPanel();
        
        // 使用 SplitPane 布局
        JSplitPane leftCenterSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, centerPanel);
        leftCenterSplit.setDividerLocation(280);
        leftCenterSplit.setResizeWeight(0.3);
        
        add(leftCenterSplit, BorderLayout.CENTER);
        add(previewPanel, BorderLayout.SOUTH);
        
        // 初始化参数列表
        refreshParamList();
    }
    
    /**
     * 创建参数搜索面板
     */
    private JPanel createParamSearchPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("参数选择"));
        panel.setPreferredSize(new Dimension(280, 400));
        
        // 搜索区域
        JPanel searchPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 2, 2, 2);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // 分类下拉框
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        categoryCombo = new JComboBox<>(PARAM_CATEGORIES);
        categoryCombo.addActionListener(e -> refreshParamList());
        searchPanel.add(categoryCombo, gbc);
        
        // 搜索框
        gbc.gridy = 1;
        searchField = new JTextField();
        searchField.setToolTipText("输入参数名或描述搜索");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refreshParamList(); }
            public void removeUpdate(DocumentEvent e) { refreshParamList(); }
            public void changedUpdate(DocumentEvent e) { refreshParamList(); }
        });
        searchPanel.add(searchField, gbc);
        
        // 搜索选项
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        regexCheckBox = new JCheckBox("正则");
        regexCheckBox.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        regexCheckBox.addActionListener(e -> refreshParamList());
        optionsPanel.add(regexCheckBox);
        
        caseSensitiveCheckBox = new JCheckBox("大小写");
        caseSensitiveCheckBox.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        caseSensitiveCheckBox.addActionListener(e -> refreshParamList());
        optionsPanel.add(caseSensitiveCheckBox);
        
        invertCheckBox = new JCheckBox("反转");
        invertCheckBox.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        invertCheckBox.addActionListener(e -> refreshParamList());
        optionsPanel.add(invertCheckBox);
        
        gbc.gridy = 2;
        searchPanel.add(optionsPanel, gbc);
        
        panel.add(searchPanel, BorderLayout.NORTH);
        
        // 参数列表
        paramListModel = new DefaultListModel<>();
        paramList = new JList<>(paramListModel);
        paramList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        paramList.setCellRenderer(new ParamListCellRenderer());
        paramList.addListSelectionListener(this::onParamSelected);
        paramList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    addCurrentParam();
                }
            }
        });
        
        JScrollPane listScroll = new JScrollPane(paramList);
        panel.add(listScroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建参数输入面板
     */
    private JPanel createParamInputPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        
        // 上部：当前参数输入
        inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("参数设置"));
        inputPanel.setPreferredSize(new Dimension(300, 150));
        
        // 参数标签面板 - 使用组合组件避免HTML渲染问题
        paramLabelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        paramNameLabel = new JLabel("请从左侧选择参数");
        paramNameLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        paramDescLabel = new JLabel("");
        paramDescLabel.setForeground(Color.GRAY);
        paramLabelPanel.add(paramNameLabel);
        paramLabelPanel.add(paramDescLabel);
        inputPanel.add(paramLabelPanel, BorderLayout.NORTH);
        
        dynamicInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        inputPanel.add(dynamicInputPanel, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        addParamButton = new JButton("添加参数 ▼");
        addParamButton.setEnabled(false);
        addParamButton.addActionListener(e -> addCurrentParam());
        buttonPanel.add(addParamButton);
        inputPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        panel.add(inputPanel, BorderLayout.NORTH);
        
        // 下部：已选参数列表
        JPanel selectedPanel = new JPanel(new BorderLayout(5, 5));
        selectedPanel.setBorder(BorderFactory.createTitledBorder("已选参数"));
        
        selectedParamModel = new DefaultListModel<>();
        selectedParamList = new JList<>(selectedParamModel);
        selectedParamList.setCellRenderer(new SelectedParamCellRenderer());
        selectedParamList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    editSelectedParam();
                }
            }
        });
        
        JScrollPane selectedScroll = new JScrollPane(selectedParamList);
        selectedPanel.add(selectedScroll, BorderLayout.CENTER);
        
        JPanel selectedButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        removeParamButton = new JButton("移除");
        removeParamButton.addActionListener(e -> removeSelectedParam());
        selectedButtonPanel.add(removeParamButton);
        
        JButton clearAllButton = new JButton("清空全部");
        clearAllButton.addActionListener(e -> clearAllParams());
        selectedButtonPanel.add(clearAllButton);
        
        selectedPanel.add(selectedButtonPanel, BorderLayout.SOUTH);
        
        panel.add(selectedPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建命令行预览面板
     */
    private JPanel createPreviewPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("命令行参数预览"));
        panel.setPreferredSize(new Dimension(600, 120));
        
        commandPreviewPane = new JEditorPane();
        commandPreviewPane.setContentType("text/html");
        commandPreviewPane.setEditable(false);
        commandPreviewPane.setFont(new Font("Consolas", Font.PLAIN, 13));
        commandPreviewPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        
        // 设置默认样式
        updateCommandPreview();
        
        JScrollPane scrollPane = new JScrollPane(commandPreviewPane);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    // ==================== 参数列表相关 ====================
    
    /**
     * 刷新参数列表
     */
    private void refreshParamList() {
        paramListModel.clear();
        
        String searchText = searchField.getText().trim();
        boolean useRegex = regexCheckBox.isSelected();
        boolean caseSensitive = caseSensitiveCheckBox.isSelected();
        boolean invert = invertCheckBox.isSelected();
        String category = (String) categoryCombo.getSelectedItem();
        
        Pattern pattern = null;
        if (useRegex && !searchText.isEmpty()) {
            try {
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                pattern = Pattern.compile(searchText, flags);
            } catch (PatternSyntaxException e) {
                // 正则表达式无效，显示错误提示
                searchField.setBackground(new Color(255, 200, 200));
                return;
            }
        }
        searchField.setBackground(Color.WHITE);
        
        // 获取要显示的参数列表
        List<String> paramsToShow;
        if ("全部".equals(category)) {
            paramsToShow = new ArrayList<>();
            for (List<String> params : CATEGORY_PARAMS.values()) {
                paramsToShow.addAll(params);
            }
        } else {
            paramsToShow = CATEGORY_PARAMS.getOrDefault(category, Collections.emptyList());
        }
        
        // 过滤参数
        Map<String, ParamMeta> allMeta = ScanConfigParser.getParamMeta();
        for (String paramName : paramsToShow) {
            ParamMeta meta = allMeta.get(paramName);
            if (meta == null) continue;
            
            boolean matches = matchesSearch(meta.getName(), meta.getDescription(), 
                                            searchText, pattern, caseSensitive);
            if (invert) matches = !matches;
            
            if (matches) {
                boolean isSelected = selectedParams.containsKey(meta.getName());
                paramListModel.addElement(new ParamListItem(meta, isSelected));
            }
        }
    }
    
    /**
     * 检查是否匹配搜索条件
     */
    private boolean matchesSearch(String name, String description, 
                                   String searchText, Pattern pattern, boolean caseSensitive) {
        if (searchText.isEmpty()) return true;
        
        if (pattern != null) {
            return pattern.matcher(name).find() || 
                   pattern.matcher(description).find();
        } else {
            String searchLower = caseSensitive ? searchText : searchText.toLowerCase();
            String nameLower = caseSensitive ? name : name.toLowerCase();
            String descLower = caseSensitive ? description : description.toLowerCase();
            return nameLower.contains(searchLower) || descLower.contains(searchLower);
        }
    }
    
    /**
     * 参数选择事件
     */
    private void onParamSelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) return;
        
        ParamListItem item = paramList.getSelectedValue();
        if (item == null) {
            currentSelectedParam = null;
            paramNameLabel.setText("请从左侧选择参数");
            paramDescLabel.setText("");
            dynamicInputPanel.removeAll();
            dynamicInputPanel.revalidate();
            dynamicInputPanel.repaint();
            addParamButton.setEnabled(false);
            return;
        }
        
        currentSelectedParam = item;
        showParamInput(item.meta);
    }
    
    /**
     * 显示参数输入控件
     */
    private void showParamInput(ParamMeta meta) {
        dynamicInputPanel.removeAll();
        
        // 更新标签 - 使用组合组件避免HTML渲染问题
        paramNameLabel.setText(meta.getName());
        paramDescLabel.setText("- " + meta.getDescription());
        
        // 根据类型创建输入控件
        currentInputComponent = createInputComponent(meta);
        if (currentInputComponent != null) {
            dynamicInputPanel.add(currentInputComponent);
            
            // 如果已选中，加载当前值
            if (selectedParams.containsKey(meta.getName())) {
                loadValueToComponent(currentInputComponent, meta, selectedParams.get(meta.getName()));
            }
        }
        
        dynamicInputPanel.revalidate();
        dynamicInputPanel.repaint();
        addParamButton.setEnabled(true);
        
        // 更新按钮文字
        if (selectedParams.containsKey(meta.getName())) {
            addParamButton.setText("更新参数 ▼");
        } else {
            addParamButton.setText("添加参数 ▼");
        }
    }
    
    /**
     * 创建输入控件
     */
    private JComponent createInputComponent(ParamMeta meta) {
        if (meta.isBoolean()) {
            JCheckBox checkBox = new JCheckBox("启用");
            checkBox.setSelected(false);
            return checkBox;
            
        } else if (meta.isInteger()) {
            int min = meta.getMinValue() != null ? meta.getMinValue().intValue() : 0;
            int max = meta.getMaxValue() != null ? meta.getMaxValue().intValue() : 100;
            int def = meta.getDefaultValue() != null ? ((Number) meta.getDefaultValue()).intValue() : min;
            JSpinner spinner = new JSpinner(new SpinnerNumberModel(def, min, max, 1));
            spinner.setPreferredSize(new Dimension(80, 25));
            return spinner;
            
        } else if (meta.isFloat()) {
            float min = meta.getMinValue() != null ? meta.getMinValue().floatValue() : 0f;
            float max = meta.getMaxValue() != null ? meta.getMaxValue().floatValue() : 100f;
            float def = meta.getDefaultValue() != null ? ((Number) meta.getDefaultValue()).floatValue() : min;
            JSpinner spinner = new JSpinner(new SpinnerNumberModel((double) def, (double) min, (double) max, 0.5));
            spinner.setPreferredSize(new Dimension(100, 25));
            return spinner;
            
        } else if (meta.hasValidValues()) {
            // 枚举类型 - 下拉框
            String[] options = getOptionsForParam(meta.getName());
            JComboBox<String> combo = new JComboBox<>(options);
            combo.setPreferredSize(new Dimension(180, 25));
            return combo;
            
        } else if (meta.getName().equals("technique")) {
            // 特殊处理 technique - 多选框
            return createTechniquePanel();
            
        } else {
            // 字符串类型 - 文本框
            JTextField textField = new JTextField(20);
            textField.setPreferredSize(new Dimension(200, 25));
            return textField;
        }
    }
    
    /**
     * 创建 technique 多选面板
     */
    private JPanel createTechniquePanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        
        String[] techniques = {"B-布尔盲注", "E-报错注入", "U-联合查询", "S-堆叠查询", "T-时间盲注", "Q-内联查询"};
        for (String tech : techniques) {
            JCheckBox cb = new JCheckBox(tech.substring(0, 1));
            cb.setToolTipText(tech);
            cb.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            panel.add(cb);
        }
        
        return panel;
    }
    
    /**
     * 获取参数的选项列表
     */
    private String[] getOptionsForParam(String paramName) {
        switch (paramName) {
            case "dbms": return DBMS_OPTIONS;
            case "os": return OS_OPTIONS;
            case "method": return METHOD_OPTIONS;
            default: return new String[]{""};
        }
    }
    
    /**
     * 加载值到控件
     */
    private void loadValueToComponent(JComponent component, ParamMeta meta, Object value) {
        if (component instanceof JCheckBox) {
            ((JCheckBox) component).setSelected(Boolean.TRUE.equals(value));
        } else if (component instanceof JSpinner) {
            ((JSpinner) component).setValue(value);
        } else if (component instanceof JComboBox) {
            ((JComboBox<?>) component).setSelectedItem(value.toString());
        } else if (component instanceof JTextField) {
            ((JTextField) component).setText(value.toString());
        } else if (component instanceof JPanel && meta.getName().equals("technique")) {
            // technique 多选
            String techStr = value.toString();
            for (Component c : component.getComponents()) {
                if (c instanceof JCheckBox) {
                    JCheckBox cb = (JCheckBox) c;
                    cb.setSelected(techStr.contains(cb.getText()));
                }
            }
        }
    }
    
    /**
     * 从控件获取值
     */
    private Object getValueFromComponent(JComponent component, ParamMeta meta) {
        if (component instanceof JCheckBox) {
            return ((JCheckBox) component).isSelected();
        } else if (component instanceof JSpinner) {
            Object val = ((JSpinner) component).getValue();
            if (meta.isInteger()) {
                return ((Number) val).intValue();
            } else {
                return ((Number) val).floatValue();
            }
        } else if (component instanceof JComboBox) {
            return ((JComboBox<?>) component).getSelectedItem();
        } else if (component instanceof JTextField) {
            return ((JTextField) component).getText();
        } else if (component instanceof JPanel && meta.getName().equals("technique")) {
            StringBuilder sb = new StringBuilder();
            for (Component c : component.getComponents()) {
                if (c instanceof JCheckBox && ((JCheckBox) c).isSelected()) {
                    sb.append(((JCheckBox) c).getText());
                }
            }
            return sb.toString();
        }
        return null;
    }
    
    // ==================== 参数操作 ====================
    
    /**
     * 添加当前参数
     */
    private void addCurrentParam() {
        if (currentSelectedParam == null || currentInputComponent == null) return;
        
        ParamMeta meta = currentSelectedParam.meta;
        Object value = getValueFromComponent(currentInputComponent, meta);
        
        // 验证值
        if (value == null) return;
        if (value instanceof String && ((String) value).isEmpty() && !meta.isBoolean()) {
            // 空字符串，跳过
            return;
        }
        if (value instanceof Boolean && !((Boolean) value)) {
            // false 值，移除
            selectedParams.remove(meta.getName());
        } else {
            selectedParams.put(meta.getName(), value);
        }
        
        refreshSelectedParamList();
        refreshParamList();
        updateCommandPreview();
        
        if (onChangeCallback != null) {
            onChangeCallback.run();
        }
    }
    
    /**
     * 刷新已选参数列表
     */
    private void refreshSelectedParamList() {
        selectedParamModel.clear();
        Map<String, ParamMeta> allMeta = ScanConfigParser.getParamMeta();
        
        for (Map.Entry<String, Object> entry : selectedParams.entrySet()) {
            ParamMeta meta = allMeta.get(entry.getKey());
            if (meta != null) {
                selectedParamModel.addElement(new SelectedParam(meta, entry.getValue()));
            }
        }
    }
    
    /**
     * 编辑选中的参数
     */
    private void editSelectedParam() {
        SelectedParam selected = selectedParamList.getSelectedValue();
        if (selected == null) return;
        
        // 在左侧列表中找到并选中该参数
        for (int i = 0; i < paramListModel.size(); i++) {
            if (paramListModel.get(i).meta.getName().equals(selected.meta.getName())) {
                paramList.setSelectedIndex(i);
                paramList.ensureIndexIsVisible(i);
                break;
            }
        }
    }
    
    /**
     * 移除选中的参数
     */
    private void removeSelectedParam() {
        SelectedParam selected = selectedParamList.getSelectedValue();
        if (selected == null) return;
        
        selectedParams.remove(selected.meta.getName());
        refreshSelectedParamList();
        refreshParamList();
        updateCommandPreview();
        
        if (onChangeCallback != null) {
            onChangeCallback.run();
        }
    }
    
    /**
     * 清空所有参数
     */
    private void clearAllParams() {
        selectedParams.clear();
        refreshSelectedParamList();
        refreshParamList();
        updateCommandPreview();
        
        if (onChangeCallback != null) {
            onChangeCallback.run();
        }
    }
    
    // ==================== 命令行预览 ====================
    
    /**
     * 更新命令行预览
     */
    private void updateCommandPreview() {
        String commandLine = generateCommandLine();
        String html = generateHighlightedHtml(commandLine);
        commandPreviewPane.setText(html);
    }
    
    /**
     * 生成命令行字符串
     */
    private String generateCommandLine() {
        StringBuilder sb = new StringBuilder();
        Map<String, ParamMeta> allMeta = ScanConfigParser.getParamMeta();
        
        for (Map.Entry<String, Object> entry : selectedParams.entrySet()) {
            String paramName = entry.getKey();
            Object value = entry.getValue();
            ParamMeta meta = allMeta.get(paramName);
            
            if (meta == null) continue;
            
            String cliName = getCliName(paramName);
            
            if (meta.isBoolean()) {
                if (Boolean.TRUE.equals(value)) {
                    sb.append(cliName).append(" ");
                }
            } else {
                String strValue = value.toString();
                if (!strValue.isEmpty()) {
                    if (strValue.contains(" ")) {
                        sb.append(cliName).append("=\"").append(strValue).append("\" ");
                    } else {
                        sb.append(cliName).append("=").append(strValue).append(" ");
                    }
                }
            }
        }
        
        return sb.toString().trim();
    }
    
    /**
     * 获取 CLI 参数名
     */
    private String getCliName(String paramName) {
        // 特殊映射
        Map<String, String> specialMapping = new HashMap<>();
        specialMapping.put("testParameter", "-p");
        specialMapping.put("optimize", "-o");
        specialMapping.put("verbose", "-v");
        specialMapping.put("db", "-D");
        specialMapping.put("tbl", "-T");
        specialMapping.put("col", "-C");
        specialMapping.put("agent", "--user-agent");
        specialMapping.put("notString", "--not-string");
        specialMapping.put("textOnly", "--text-only");
        specialMapping.put("skipStatic", "--skip-static");
        specialMapping.put("paramExclude", "--param-exclude");
        specialMapping.put("timeSec", "--time-sec");
        specialMapping.put("proxyCred", "--proxy-cred");
        specialMapping.put("randomAgent", "--random-agent");
        specialMapping.put("forceSSL", "--force-ssl");
        specialMapping.put("skipUrlEncode", "--skip-urlencode");
        specialMapping.put("keepAlive", "--keep-alive");
        specialMapping.put("nullConnection", "--null-connection");
        specialMapping.put("getBanner", "--banner");
        specialMapping.put("getCurrentUser", "--current-user");
        specialMapping.put("getCurrentDb", "--current-db");
        specialMapping.put("isDba", "--is-dba");
        specialMapping.put("getUsers", "--users");
        specialMapping.put("getDbs", "--dbs");
        specialMapping.put("getTables", "--tables");
        specialMapping.put("getColumns", "--columns");
        specialMapping.put("dumpTable", "--dump");
        specialMapping.put("dumpAll", "--dump-all");
        specialMapping.put("crawlDepth", "--crawl");
        specialMapping.put("flushSession", "--flush-session");
        specialMapping.put("freshQueries", "--fresh-queries");
        
        if (specialMapping.containsKey(paramName)) {
            return specialMapping.get(paramName);
        }
        
        // 驼峰转短横线
        return "--" + paramName.replaceAll("([a-z])([A-Z])", "$1-$2").toLowerCase();
    }
    
    /**
     * 生成带高亮的 HTML
     */
    private String generateHighlightedHtml(String commandLine) {
        if (commandLine.isEmpty()) {
            return "<html><body style='font-family:Consolas,monospace;font-size:12px;padding:5px;color:#888;'>" +
                   "<i>暂无参数，请从左侧选择参数添加</i></body></html>";
        }
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family:Consolas,monospace;font-size:12px;padding:5px;'>");
        
        // 分割参数
        String[] parts = commandLine.split("\\s+");
        for (String part : parts) {
            if (part.contains("=")) {
                String[] kv = part.split("=", 2);
                // 参数名 - 蓝色
                html.append("<span style='color:#0066CC;font-weight:bold;'>").append(escapeHtml(kv[0])).append("</span>");
                html.append("<span style='color:#666;'>=</span>");
                // 参数值 - 绿色
                if (kv.length > 1) {
                    html.append("<span style='color:#009933;'>").append(escapeHtml(kv[1])).append("</span>");
                }
            } else {
                // 布尔参数 - 紫色
                html.append("<span style='color:#9933CC;font-weight:bold;'>").append(escapeHtml(part)).append("</span>");
            }
            html.append(" ");
        }
        
        html.append("</body></html>");
        return html.toString();
    }
    
    /**
     * HTML 转义
     */
    private String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
    
    // ==================== 公开方法 ====================
    
    /**
     * 获取命令行参数字符串
     */
    public String getCommandLine() {
        return generateCommandLine();
    }
    
    /**
     * 从参数字符串加载
     */
    public void loadFromParamString(String paramString) {
        selectedParams.clear();
        
        if (paramString == null || paramString.trim().isEmpty()) {
            refreshSelectedParamList();
            refreshParamList();
            updateCommandPreview();
            return;
        }
        
        // 使用解析器解析
        ScanConfig config = ScanConfig.fromCommandLineStringSafe(paramString);
        Map<String, Object> options = config.toOptionsMap();
        
        selectedParams.putAll(options);
        
        refreshSelectedParamList();
        refreshParamList();
        updateCommandPreview();
    }
    
    /**
     * 设置变更回调
     */
    public void setOnChangeCallback(Runnable callback) {
        this.onChangeCallback = callback;
    }
    
    /**
     * 获取已选参数Map
     */
    public Map<String, Object> getSelectedParams() {
        return new LinkedHashMap<>(selectedParams);
    }
    
    // ==================== 内部类 ====================
    
    /**
     * 参数列表项
     */
    private static class ParamListItem {
        final ParamMeta meta;
        final boolean isSelected;
        
        ParamListItem(ParamMeta meta, boolean isSelected) {
            this.meta = meta;
            this.isSelected = isSelected;
        }
        
        @Override
        public String toString() {
            return meta.getName();
        }
    }
    
    /**
     * 参数列表渲染器 - 使用JPanel组合避免HTML渲染问题
     */
    private static class ParamListCellRenderer extends JPanel implements ListCellRenderer<ParamListItem> {
        private final JLabel nameLabel;
        private final JLabel descLabel;
        private final Color selectedBg;
        private final Color normalBg;
        private final Color addedBg;
        
        public ParamListCellRenderer() {
            setLayout(new FlowLayout(FlowLayout.LEFT, 5, 2));
            setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
            
            nameLabel = new JLabel();
            nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
            
            descLabel = new JLabel();
            descLabel.setForeground(Color.GRAY);
            
            add(nameLabel);
            add(descLabel);
            
            selectedBg = UIManager.getColor("List.selectionBackground");
            normalBg = UIManager.getColor("List.background");
            addedBg = new Color(220, 255, 220);
        }
        
        @Override
        public Component getListCellRendererComponent(JList<? extends ParamListItem> list, 
                ParamListItem value, int index, boolean isSelected, boolean cellHasFocus) {
            
            if (value != null) {
                nameLabel.setText(value.meta.getName());
                descLabel.setText("- " + value.meta.getDescription());
                
                if (isSelected) {
                    setBackground(selectedBg);
                    nameLabel.setForeground(UIManager.getColor("List.selectionForeground"));
                    descLabel.setForeground(UIManager.getColor("List.selectionForeground"));
                } else if (value.isSelected) {
                    setBackground(addedBg);
                    nameLabel.setForeground(Color.BLACK);
                    descLabel.setForeground(Color.GRAY);
                } else {
                    setBackground(normalBg);
                    nameLabel.setForeground(Color.BLACK);
                    descLabel.setForeground(Color.GRAY);
                }
            }
            
            return this;
        }
    }
    
    /**
     * 已选参数项
     */
    private static class SelectedParam {
        final ParamMeta meta;
        final Object value;
        
        SelectedParam(ParamMeta meta, Object value) {
            this.meta = meta;
            this.value = value;
        }
        
        @Override
        public String toString() {
            return meta.getName() + " = " + value;
        }
    }
    
    /**
     * 已选参数渲染器 - 使用JPanel组合避免HTML渲染问题
     */
    private static class SelectedParamCellRenderer extends JPanel implements ListCellRenderer<SelectedParam> {
        private final JLabel nameLabel;
        private final JLabel equalsLabel;
        private final JLabel valueLabel;
        private final Color selectedBg;
        private final Color normalBg;
        
        public SelectedParamCellRenderer() {
            setLayout(new FlowLayout(FlowLayout.LEFT, 3, 2));
            setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
            
            nameLabel = new JLabel();
            nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
            nameLabel.setForeground(new Color(0, 102, 204)); // #0066CC
            
            equalsLabel = new JLabel("=");
            
            valueLabel = new JLabel();
            valueLabel.setForeground(new Color(0, 153, 51)); // #009933
            
            add(nameLabel);
            add(equalsLabel);
            add(valueLabel);
            
            selectedBg = UIManager.getColor("List.selectionBackground");
            normalBg = UIManager.getColor("List.background");
        }
        
        @Override
        public Component getListCellRendererComponent(JList<? extends SelectedParam> list,
                SelectedParam value, int index, boolean isSelected, boolean cellHasFocus) {
            
            if (value != null) {
                nameLabel.setText(value.meta.getName());
                
                String valueStr = value.value.toString();
                if (value.meta.isBoolean()) {
                    valueStr = Boolean.TRUE.equals(value.value) ? "\u2713" : "\u2717";
                }
                valueLabel.setText(valueStr);
                
                if (isSelected) {
                    setBackground(selectedBg);
                    Color selFg = UIManager.getColor("List.selectionForeground");
                    nameLabel.setForeground(selFg);
                    equalsLabel.setForeground(selFg);
                    valueLabel.setForeground(selFg);
                } else {
                    setBackground(normalBg);
                    nameLabel.setForeground(new Color(0, 102, 204));
                    equalsLabel.setForeground(Color.BLACK);
                    valueLabel.setForeground(new Color(0, 153, 51));
                }
            }
            
            return this;
        }
    }
    
    // ==================== 静态初始化 ====================
    
    private static void initCategoryParams() {
        CATEGORY_PARAMS.put("Detection 检测", Arrays.asList(
            "level", "risk", "string", "notString", "regexp", "code", "smart", "textOnly", "titles"
        ));
        CATEGORY_PARAMS.put("Injection 注入", Arrays.asList(
            "testParameter", "skip", "skipStatic", "paramExclude", "dbms", "os", "prefix", "suffix", "tamper"
        ));
        CATEGORY_PARAMS.put("Techniques 技术", Arrays.asList(
            "technique", "timeSec"
        ));
        CATEGORY_PARAMS.put("Request 请求", Arrays.asList(
            "method", "data", "cookie", "agent", "referer", "headers", "proxy", "proxyCred",
            "delay", "timeout", "retries", "randomAgent", "tor", "forceSSL", "skipUrlEncode"
        ));
        CATEGORY_PARAMS.put("Optimization 优化", Arrays.asList(
            "optimize", "keepAlive", "nullConnection", "threads"
        ));
        CATEGORY_PARAMS.put("Enumeration 枚举", Arrays.asList(
            "getBanner", "getCurrentUser", "getCurrentDb", "isDba", "getUsers", "getDbs",
            "getTables", "getColumns", "dumpTable", "dumpAll", "db", "tbl", "col"
        ));
        CATEGORY_PARAMS.put("General 通用", Arrays.asList(
            "batch", "forms", "crawlDepth", "flushSession", "freshQueries", "verbose"
        ));
    }
}
