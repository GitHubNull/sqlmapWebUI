package com.sqlmapwebui.burp.ui.dialog;

import com.sqlmapwebui.burp.config.ConfigManager;
import com.sqlmapwebui.burp.model.TitleRule;
import com.sqlmapwebui.burp.model.TitleSourceType;
import com.sqlmapwebui.burp.util.TitleExtractor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.List;

/**
 * 标题提取测试对话框
 * 允许用户粘贴 HTTP 请求内容并测试标题提取规则
 */
public class TitleTestDialog extends JDialog {

    private final ConfigManager configManager;

    // UI 组件
    private JTextArea requestArea;
    private JTextField resultField;
    private JLabel matchedRuleLabel;

    public TitleTestDialog(ConfigManager configManager, Object ignored) {
        super((Frame) null, "标题提取测试", true);
        this.configManager = configManager;
        
        initializeComponents();
        layoutComponents();
    }

    private void initializeComponents() {
        // 请求输入区
        requestArea = new JTextArea(15, 50);
        requestArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        requestArea.setLineWrap(true);
        requestArea.setWrapStyleWord(true);
        requestArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateResult();
            }
            @Override
            public void removeUpdate(DocumentEvent e) {
                updateResult();
            }
            @Override
            public void changedUpdate(DocumentEvent e) {
                updateResult();
            }
        });

        // 结果显示区
        resultField = new JTextField(50);
        resultField.setEditable(false);
        resultField.setFont(new Font("SansSerif", Font.BOLD, 14));
        resultField.setForeground(new Color(39, 174, 96));

        // 匹配规则标签
        matchedRuleLabel = new JLabel(" ");
        matchedRuleLabel.setForeground(new Color(52, 152, 219));
    }

    private void updateResult() {
        String requestContent = requestArea.getText();
        if (requestContent.trim().isEmpty()) {
            resultField.setText("(请输入 HTTP 请求内容)");
            resultField.setForeground(Color.GRAY);
            matchedRuleLabel.setText(" ");
            return;
        }

        try {
            // 获取规则列表
            List<TitleRule> rules = configManager.getTitleRules();
            String fallback = configManager.getTitleFallback();
            int maxLength = configManager.getTitleMaxLength();
            
            // 使用新的多规则提取方法
            TitleExtractor.ExtractionResult result = TitleExtractor.extractWithInfo(
                requestContent, rules, fallback, maxLength);
            
            resultField.setText(result.getTitle());
            resultField.setForeground(new Color(39, 174, 96));
            
            if (result.getMatchedRuleName() != null) {
                matchedRuleLabel.setText("匹配规则: " + result.getMatchedRuleName() +
                    " (" + getSourceTypeDisplayName(result.getMatchedSourceType()) + ")");
            } else {
                matchedRuleLabel.setText("使用回退标题");
            }
        } catch (Exception e) {
            resultField.setText("错误: " + e.getMessage());
            resultField.setForeground(new Color(231, 76, 60));
            matchedRuleLabel.setText(" ");
        }
    }

    private void layoutComponents() {
        setLayout(new BorderLayout(10, 10));
        
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 顶部：请求输入
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "HTTP 请求内容 (粘贴完整请求)",
            TitledBorder.LEFT,
            TitledBorder.TOP
        ));
        JScrollPane requestScrollPane = new JScrollPane(requestArea);
        requestScrollPane.setPreferredSize(new Dimension(600, 250));
        requestPanel.add(requestScrollPane, BorderLayout.CENTER);
        
        // 示例按钮
        JPanel examplePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton loadExampleBtn = new JButton("加载示例请求");
        loadExampleBtn.addActionListener(e -> loadExampleRequest());
        examplePanel.add(loadExampleBtn);
        JButton clearBtn = new JButton("清空");
        clearBtn.addActionListener(e -> {
            requestArea.setText("");
            resultField.setText("");
            matchedRuleLabel.setText(" ");
        });
        examplePanel.add(clearBtn);
        requestPanel.add(examplePanel, BorderLayout.SOUTH);
        
        mainPanel.add(requestPanel, BorderLayout.NORTH);

        // 中间：规则说明
        JPanel infoPanel = createInfoPanel();
        mainPanel.add(infoPanel, BorderLayout.CENTER);

        // 底部：结果显示和按钮
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 10));
        
        JPanel resultPanel = new JPanel(new BorderLayout(5, 5));
        resultPanel.setBorder(BorderFactory.createTitledBorder("提取结果"));
        
        JPanel titlePanel = new JPanel(new BorderLayout(5, 0));
        titlePanel.add(new JLabel("标题: "), BorderLayout.WEST);
        titlePanel.add(resultField, BorderLayout.CENTER);
        resultPanel.add(titlePanel, BorderLayout.NORTH);
        resultPanel.add(matchedRuleLabel, BorderLayout.SOUTH);
        
        bottomPanel.add(resultPanel, BorderLayout.NORTH);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("关闭");
        closeBtn.addActionListener(e -> dispose());
        buttonPanel.add(closeBtn);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);

        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        add(mainPanel, BorderLayout.CENTER);
        
        setSize(700, 550);
        setLocationRelativeTo(null);
    }

    private JPanel createInfoPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("规则测试说明"));
        
        String info = "<html><body style='padding: 5px;'>" +
            "<p>此对话框将使用当前配置的规则列表进行测试。</p>" +
            "<p><b>匹配顺序:</b> 按优先级从低到高依次尝试，首次成功匹配即返回。</p>" +
            "<p><b>默认规则:</b> URL路径规则始终作为最终兜底。</p>" +
            "<p><b>提示:</b> 在配置面板中添加/编辑规则后可在此测试效果。</p>" +
            "</body></html>";
        
        JLabel infoLabel = new JLabel(info);
        infoLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        panel.add(infoLabel, BorderLayout.CENTER);
        
        // 显示当前规则数量
        int ruleCount = configManager.getTitleRules().size();
        JLabel countLabel = new JLabel("当前规则数量: " + ruleCount);
        countLabel.setForeground(Color.GRAY);
        panel.add(countLabel, BorderLayout.SOUTH);
        
        return panel;
    }

    private void loadExampleRequest() {
        String example = "POST /api/user/profile HTTP/1.1\r\n" +
            "Host: example.com\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: 45\r\n" +
            "Cookie: session=abc123\r\n" +
            "\r\n" +
            "{\"username\":\"admin\",\"action\":\"update\"}";
        requestArea.setText(example);
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
}
