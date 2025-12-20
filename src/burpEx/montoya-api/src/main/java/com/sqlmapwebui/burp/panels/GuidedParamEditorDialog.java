package com.sqlmapwebui.burp.panels;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * 引导式参数编辑器对话框
 * 封装 GuidedParamEditor 组件为模态对话框
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class GuidedParamEditorDialog extends JDialog {
    
    /** 编辑器组件 */
    private final GuidedParamEditor editor;
    
    /** 用户是否确认 */
    private boolean confirmed = false;
    
    /** 结果参数字符串 */
    private String resultParamString = "";
    
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
        super(owner, title, ModalityType.APPLICATION_MODAL);
        
        this.editor = new GuidedParamEditor(initialParams);
        
        initializeDialog();
    }
    
    /**
     * 初始化对话框
     */
    private void initializeDialog() {
        setLayout(new BorderLayout(10, 10));
        
        // 主编辑器面板
        add(editor, BorderLayout.CENTER);
        
        // 底部按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
        
        JButton okButton = new JButton("确定");
        okButton.setPreferredSize(new Dimension(80, 28));
        okButton.addActionListener(e -> {
            confirmed = true;
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
        setSize(800, 650);
        setMinimumSize(new Dimension(700, 500));
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
     * 获取编辑器组件（用于高级操作）
     */
    public GuidedParamEditor getEditor() {
        return editor;
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
        Window window = owner instanceof Window ? (Window) owner : 
                        SwingUtilities.getWindowAncestor(owner);
        
        GuidedParamEditorDialog dialog = new GuidedParamEditorDialog(window, title, initialParams);
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
}
