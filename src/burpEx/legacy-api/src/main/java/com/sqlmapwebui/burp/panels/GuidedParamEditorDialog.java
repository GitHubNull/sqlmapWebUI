package com.sqlmapwebui.burp.panels;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * 引导式参数编辑器对话框
 * 封装 GuidedParamEditor 组件为模态对话框
 * 支持新增和编辑模式，在一个界面完成名称、描述和参数配置
 * 
 * @author SQLMap WebUI Team
 * @version 1.1.0
 */
public class GuidedParamEditorDialog extends JDialog {
    
    /** 编辑器组件 */
    private final GuidedParamEditor editor;
    
    /** 用户是否确认 */
    private boolean confirmed = false;
    
    /** 结果参数字符串 */
    private String resultParamString = "";
    
    /** 结果配置名称 */
    private String resultName = "";
    
    /** 结果配置描述 */
    private String resultDescription = "";
    
    /** 配置名称输入框 */
    private JTextField nameField;
    
    /** 配置描述输入框 */
    private JTextField descField;
    
    /** 初始配置名称（编辑模式） */
    private String presetName;
    
    /** 初始配置描述（编辑模式） */
    private String presetDescription;
    
    /**
     * 构造函数
     * 
     * @param owner 父窗口
     * @param title 对话框标题
     */
    public GuidedParamEditorDialog(Window owner, String title) {
        this(owner, title, null);
    }
    
    /**
     * 构造函数（带初始参数）
     * 
     * @param owner 父窗口
     * @param title 对话框标题
     * @param initialParams 初始参数字符串
     */
    public GuidedParamEditorDialog(Window owner, String title, String initialParams) {
        this(owner, title, initialParams, null, null);
    }
    
    /**
     * 构造函数（带配置信息，用于编辑模式）
     * 
     * @param owner 父窗口
     * @param title 对话框标题
     * @param initialParams 初始参数字符串
     * @param presetName 配置名称（可为null）
     * @param presetDescription 配置描述（可为null）
     */
    public GuidedParamEditorDialog(Window owner, String title, String initialParams, 
                                   String presetName, String presetDescription) {
        super(owner, title, ModalityType.APPLICATION_MODAL);
        
        this.editor = new GuidedParamEditor(initialParams);
        this.presetName = presetName;
        this.presetDescription = presetDescription;
        
        initializeDialog();
    }
    
    /**
     * 初始化对话框
     */
    private void initializeDialog() {
        setLayout(new BorderLayout(10, 10));
        
        // 顶部配置信息输入面板（始终显示可编辑的输入框）
        JPanel infoPanel = createPresetInputPanel();
        add(infoPanel, BorderLayout.NORTH);
        
        // 主编辑器面板
        add(editor, BorderLayout.CENTER);
        
        // 底部按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
        
        JButton okButton = new JButton("保存");
        okButton.setPreferredSize(new Dimension(80, 28));
        okButton.addActionListener(e -> {
            // 验证名称不能为空
            String name = nameField.getText().trim();
            if (name.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入配置名称", "提示", JOptionPane.WARNING_MESSAGE);
                nameField.requestFocus();
                return;
            }
            
            confirmed = true;
            resultName = name;
            resultDescription = descField.getText().trim();
            resultParamString = editor.getCommandLine();
            dispose();
        });
        buttonPanel.add(okButton);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.setPreferredSize(new Dimension(80, 28));
        cancelButton.addActionListener(e -> {
            confirmed = false;
            dispose();
        });
        buttonPanel.add(cancelButton);
        
        add(buttonPanel, BorderLayout.SOUTH);
        
        // 对话框设置
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setSize(900, 780);
        setMinimumSize(new Dimension(800, 650));
        setLocationRelativeTo(getOwner());
        
        // 窗口关闭事件
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                confirmed = false;
            }
        });
        
        // ESC 键关闭
        getRootPane().registerKeyboardAction(
            e -> {
                confirmed = false;
                dispose();
            },
            KeyStroke.getKeyStroke("ESCAPE"),
            JComponent.WHEN_IN_FOCUSED_WINDOW
        );
        
        // 设置默认按钮
        getRootPane().setDefaultButton(okButton);
    }
    
    /**
     * 显示对话框并返回结果
     * 
     * @return 如果用户确认则返回参数字符串，否则返回 null
     */
    public String showDialog() {
        setVisible(true);
        return confirmed ? resultParamString : null;
    }
    
    /**
     * 是否已确认
     */
    public boolean isConfirmed() {
        return confirmed;
    }
    
    /**
     * 获取结果参数字符串
     */
    public String getResultParamString() {
        return resultParamString;
    }
    
    /**
     * 获取结果配置名称
     */
    public String getResultName() {
        return resultName;
    }
    
    /**
     * 获取结果配置描述
     */
    public String getResultDescription() {
        return resultDescription;
    }
    
    /**
     * 获取编辑器组件（用于高级操作）
     */
    public GuidedParamEditor getEditor() {
        return editor;
    }
    
    /**
     * 创建配置输入面板（可编辑的名称和描述输入框）
     */
    private JPanel createPresetInputPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(10, 10, 5, 10),
            BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(99, 102, 241, 80), 1),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
            )
        ));
        panel.setBackground(new Color(99, 102, 241, 20));
        
        // 配置名称行
        JPanel nameRow = new JPanel(new BorderLayout(5, 0));
        nameRow.setOpaque(false);
        nameRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        
        JPanel nameLabelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        nameLabelPanel.setOpaque(false);
        nameLabelPanel.setPreferredSize(new Dimension(100, 25));
        JLabel nameIcon = new JLabel("● ");
        nameIcon.setForeground(new Color(99, 102, 241));
        nameLabelPanel.add(nameIcon);
        JLabel nameLabel = new JLabel("配置名称");
        nameLabel.setForeground(Color.GRAY);
        nameLabelPanel.add(nameLabel);
        JLabel requiredMark = new JLabel(" *");
        requiredMark.setForeground(Color.RED);
        nameLabelPanel.add(requiredMark);
        nameRow.add(nameLabelPanel, BorderLayout.WEST);
        
        nameField = new JTextField();
        nameField.setText(presetName != null ? presetName : "");
        nameField.setFont(nameField.getFont().deriveFont(Font.BOLD));
        nameRow.add(nameField, BorderLayout.CENTER);
        
        panel.add(nameRow);
        panel.add(Box.createVerticalStrut(6));
        
        // 配置描述行
        JPanel descRow = new JPanel(new BorderLayout(5, 0));
        descRow.setOpaque(false);
        descRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        
        JPanel descLabelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        descLabelPanel.setOpaque(false);
        descLabelPanel.setPreferredSize(new Dimension(100, 25));
        JLabel descIcon = new JLabel("○ ");
        descIcon.setForeground(new Color(99, 102, 241));
        descLabelPanel.add(descIcon);
        JLabel descLabel = new JLabel("描    述");
        descLabel.setForeground(Color.GRAY);
        descLabelPanel.add(descLabel);
        descRow.add(descLabelPanel, BorderLayout.WEST);
        
        descField = new JTextField();
        descField.setText(presetDescription != null ? presetDescription : "");
        descField.setFont(descField.getFont().deriveFont(Font.ITALIC));
        descRow.add(descField, BorderLayout.CENTER);
        
        panel.add(descRow);
        
        return panel;
    }
    
    // ==================== 静态便捷方法 ====================
    
    /**
     * 显示引导式参数编辑对话框
     * 
     * @param owner 父组件
     * @param title 对话框标题
     * @return 参数字符串，如果取消则返回 null
     */
    public static String showEditor(Component owner, String title) {
        return showEditor(owner, title, null);
    }
    
    /**
     * 显示引导式参数编辑对话框（带初始参数）
     * 
     * @param owner 父组件
     * @param title 对话框标题
     * @param initialParams 初始参数字符串
     * @return 参数字符串，如果取消则返回 null
     */
    public static String showEditor(Component owner, String title, String initialParams) {
        return showEditor(owner, title, initialParams, null, null);
    }
    
    /**
     * 显示引导式参数编辑对话框（带配置信息）
     * 
     * @param owner 父组件
     * @param title 对话框标题
     * @param initialParams 初始参数字符串
     * @param presetName 配置名称（可为null）
     * @param presetDescription 配置描述（可为null）
     * @return 参数字符串，如果取消则返回 null
     */
    public static String showEditor(Component owner, String title, String initialParams,
                                    String presetName, String presetDescription) {
        Window window = owner instanceof Window ? (Window) owner : 
                        SwingUtilities.getWindowAncestor(owner);
        
        GuidedParamEditorDialog dialog = new GuidedParamEditorDialog(
            window, title, initialParams, presetName, presetDescription);
        return dialog.showDialog();
    }
    
    /**
     * 显示新建参数配置对话框
     * 
     * @param owner 父组件
     * @return 参数字符串，如果取消则返回 null
     */
    public static String showNewParamDialog(Component owner) {
        return showEditor(owner, "引导式参数配置 - 新建", null);
    }
    
    /**
     * 显示编辑参数配置对话框
     * 
     * @param owner 父组件
     * @param existingParams 现有参数字符串
     * @return 参数字符串，如果取消则返回 null
     */
    public static String showEditParamDialog(Component owner, String existingParams) {
        return showEditor(owner, "引导式参数配置 - 编辑", existingParams);
    }
    
    /**
     * 显示编辑参数配置对话框（带配置信息）
     * 
     * @param owner 父组件
     * @param existingParams 现有参数字符串
     * @param presetName 配置名称
     * @param presetDescription 配置描述
     * @return 参数字符串，如果取消则返回 null
     */
    public static String showEditParamDialog(Component owner, String existingParams,
                                             String presetName, String presetDescription) {
        return showEditor(owner, "引导式参数配置 - 编辑", existingParams, 
                         presetName, presetDescription);
    }
}
