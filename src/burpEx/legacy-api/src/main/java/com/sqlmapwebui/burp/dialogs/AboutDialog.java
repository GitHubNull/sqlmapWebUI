package com.sqlmapwebui.burp.dialogs;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.geom.*;

/**
 * 关于/帮助对话框
 * 包含四个标签页：关于、使用帮助、开源协议、免责声明
 */
public class AboutDialog extends JDialog {
    
    private static final String VERSION = "1.7.9";
    
    /**
     * 自定义Logo组件 - 绘制盾牌+注入针头图标
     */
    private static class LogoPanel extends JPanel {
        private final int size;
        
        public LogoPanel(int size) {
            this.size = size;
            setPreferredSize(new Dimension(size, size));
            setOpaque(false);
        }
        
        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2d = (Graphics2D) g.create();
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            
            float scale = size / 64f;
            
            // 盾牌路径
            Path2D shield = new Path2D.Float();
            shield.moveTo(32 * scale, 4 * scale);  // 顶部中心
            shield.lineTo(56 * scale, 12 * scale); // 右上
            shield.lineTo(56 * scale, 28 * scale); // 右中
            shield.quadTo(56 * scale, 48 * scale, 32 * scale, 60 * scale); // 右曲线到底部
            shield.quadTo(8 * scale, 48 * scale, 8 * scale, 28 * scale);   // 左曲线
            shield.lineTo(8 * scale, 12 * scale);  // 左上
            shield.closePath();
            
            // 渐变填充
            GradientPaint gradient = new GradientPaint(
                0, 0, new Color(139, 92, 246),      // 紫色
                size, size, new Color(6, 182, 212)   // 青色
            );
            g2d.setPaint(gradient);
            g2d.fill(shield);
            
            // 盾牌边框
            g2d.setColor(new Color(255, 255, 255, 60));
            g2d.setStroke(new BasicStroke(2 * scale));
            g2d.draw(shield);
            
            // 注射器主体
            g2d.setColor(new Color(255, 255, 255, 240));
            RoundRectangle2D syringe = new RoundRectangle2D.Float(
                28 * scale, 16 * scale, 8 * scale, 20 * scale, 3 * scale, 3 * scale
            );
            g2d.fill(syringe);
            
            // 注射器刻度
            g2d.setColor(new Color(139, 92, 246, 150));
            g2d.fillRect((int)(30 * scale), (int)(20 * scale), (int)(4 * scale), (int)(2 * scale));
            g2d.fillRect((int)(30 * scale), (int)(26 * scale), (int)(4 * scale), (int)(2 * scale));
            
            // 针头
            g2d.setColor(new Color(255, 255, 255, 230));
            Path2D needle = new Path2D.Float();
            needle.moveTo(29 * scale, 36 * scale);
            needle.lineTo(35 * scale, 36 * scale);
            needle.lineTo(33 * scale, 48 * scale);
            needle.lineTo(31 * scale, 48 * scale);
            needle.closePath();
            g2d.fill(needle);
            
            // 针尖
            Path2D tip = new Path2D.Float();
            tip.moveTo(31 * scale, 48 * scale);
            tip.lineTo(33 * scale, 48 * scale);
            tip.lineTo(32 * scale, 54 * scale);
            tip.closePath();
            g2d.fill(tip);
            
            // 推杆
            g2d.setColor(new Color(255, 255, 255, 200));
            RoundRectangle2D plunger = new RoundRectangle2D.Float(
                29 * scale, 10 * scale, 6 * scale, 6 * scale, 2 * scale, 2 * scale
            );
            g2d.fill(plunger);
            
            g2d.dispose();
        }
    }
    
    public AboutDialog(Frame parent) {
        super(parent, "关于 SQLMap WebUI Extension", true);
        initializeUI();
    }
    
    public AboutDialog(Dialog parent) {
        super(parent, "关于 SQLMap WebUI Extension", true);
        initializeUI();
    }
    
    private void initializeUI() {
        setLayout(new BorderLayout());
        setSize(700, 550);
        setLocationRelativeTo(getParent());
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        
        // 创建标签页面板
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Tab 1: 关于
        tabbedPane.addTab("关于", createAboutPanel());
        
        // Tab 2: 使用帮助
        tabbedPane.addTab("使用帮助", createHelpPanel());
        
        // Tab 3: 开源协议
        tabbedPane.addTab("开源协议", createLicensePanel());
        
        // Tab 4: 免责声明
        tabbedPane.addTab("免责声明", createDisclaimerPanel());
        
        add(tabbedPane, BorderLayout.CENTER);
        
        // 底部按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton closeButton = new JButton("关闭");
        closeButton.addActionListener(e -> dispose());
        buttonPanel.add(closeButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    /**
     * 创建关于面板
     */
    private JPanel createAboutPanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        // 顶部：图标和基本信息
        JPanel headerPanel = new JPanel(new BorderLayout(15, 10));
        
        // 创建自定义Logo组件
        LogoPanel logoPanel = new LogoPanel(72);
        headerPanel.add(logoPanel, BorderLayout.WEST);
        
        // 标题和版本
        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.Y_AXIS));
        
        JLabel titleLabel = new JLabel("SQLMap WebUI Extension");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 20));
        titlePanel.add(titleLabel);
        titlePanel.add(Box.createVerticalStrut(5));
        
        JLabel versionLabel = new JLabel("版本 " + VERSION + " (Legacy API)");
        versionLabel.setFont(new Font("SansSerif", Font.PLAIN, 14));
        versionLabel.setForeground(new Color(0, 120, 215));
        titlePanel.add(versionLabel);
        titlePanel.add(Box.createVerticalStrut(10));
        
        JLabel descLabel1 = new JLabel("一个用于 Burp Suite 的 SQLMap 集成插件，");
        descLabel1.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        titlePanel.add(descLabel1);
        
        JLabel descLabel2 = new JLabel("可快速将HTTP请求发送至SQLMap后端进行SQL注入检测。");
        descLabel2.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        titlePanel.add(descLabel2);
        
        headerPanel.add(titlePanel, BorderLayout.CENTER);
        panel.add(headerPanel, BorderLayout.NORTH);
        
        // 中部：功能特性
        String htmlContent = "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', sans-serif; font-size: 12px; }" +
            "h3 { margin: 10px 0 5px 0; color: #333; }" +
            ".feature-grid { margin: 5px 0; }" +
            ".feature { margin: 3px 0; padding: 5px 10px; background: #f5f5f5; border-radius: 4px; }" +
            ".tech-tag { display: inline-block; margin: 2px; padding: 3px 8px; background: #e3f2fd; border-radius: 3px; font-size: 11px; }" +
            "</style></head><body>" +
            "<h3>功能特性</h3>" +
            "<div class='feature-grid'>" +
            "<div class='feature'>✓ 右键快速发送请求到SQLMap</div>" +
            "<div class='feature'>✓ 扫描配置预设管理（默认/常用/历史）</div>" +
            "<div class='feature'>✓ 引导式参数配置</div>" +
            "<div class='feature'>✓ 支持多种扫描参数自定义</div>" +
            "<div class='feature'>✓ 请求去重与智能过滤</div>" +
            "<div class='feature'>✓ 二进制内容检测与警告</div>" +
            "</div>" +
            "<h3>技术栈</h3>" +
            "<div>" +
            "<span class='tech-tag'>Java 11</span>" +
            "<span class='tech-tag'>Burp Suite Legacy API</span>" +
            "<span class='tech-tag'>Swing</span>" +
            "<span class='tech-tag'>SQLite</span>" +
            "</div>" +
            "<h3>链接</h3>" +
            "<div>GitHub: <a href='https://github.com/GitHubNull/sqlmapWebUI'>https://github.com/GitHubNull/sqlmapWebUI</a></div>" +
            "</body></html>";
        
        JEditorPane editorPane = createHtmlPane(htmlContent);
        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建使用帮助面板
     */
    private JPanel createHelpPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));
        
        String htmlContent = "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', sans-serif; font-size: 12px; line-height: 1.6; }" +
            "h2 { color: #1976d2; margin: 15px 0 10px 0; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }" +
            "h3 { color: #333; margin: 10px 0 5px 0; }" +
            "p { margin: 5px 0; }" +
            "ul { margin: 5px 0 10px 20px; }" +
            "li { margin: 3px 0; }" +
            "code { background: #f5f5f5; padding: 2px 5px; border-radius: 3px; font-family: Consolas, monospace; }" +
            ".section { margin-bottom: 15px; padding: 10px; background: #fafafa; border-radius: 5px; }" +
            "</style></head><body>" +
            
            "<h2>快速开始</h2>" +
            "<div class='section'>" +
            "<h3>1. 配置服务器</h3>" +
            "<p>在「服务器配置」标签页中设置SQLMap WebUI后端地址（默认: http://127.0.0.1:8775）</p>" +
            "<p>点击「测试连接」验证连接状态</p>" +
            
            "<h3>2. 发送扫描请求</h3>" +
            "<p>在Burp的任意HTTP请求上右键，选择「Send to SQLMap WebUI」</p>" +
            "<p>可选择使用默认配置或选择已保存的配置</p>" +
            
            "<h3>3. 查看扫描结果</h3>" +
            "<p>打开SQLMap WebUI的Web界面查看扫描任务状态和结果</p>" +
            "</div>" +
            
            "<h2>扫描配置管理</h2>" +
            "<div class='section'>" +
            "<h3>默认配置</h3>" +
            "<p>设置全局默认扫描参数，每次发送请求时自动应用。</p>" +
            
            "<h3>常用配置</h3>" +
            "<p>保存常用的配置组合，支持增删改查。右键菜单可快速选择使用。</p>" +
            "<p>点击「引导式添加/编辑」可视化配置扫描参数。</p>" +
            
            "<h3>历史配置</h3>" +
            "<p>自动记录历史扫描使用过的配置，方便复用。</p>" +
            "</div>" +
            
            "<h2>常用参数说明</h2>" +
            "<div class='section'>" +
            "<ul>" +
            "<li><code>--level</code>: 检测等级 (1-5)，越高检测越全面</li>" +
            "<li><code>--risk</code>: 风险等级 (1-3)，越高测试越激进</li>" +
            "<li><code>--technique</code>: 注入技术 (BEUSTQ)</li>" +
            "<li><code>--threads</code>: 并发线程数</li>" +
            "<li><code>--batch</code>: 非交互模式，自动使用默认值</li>" +
            "<li><code>--random-agent</code>: 随机User-Agent</li>" +
            "</ul>" +
            "</div>" +
            
            "<h2>注意事项</h2>" +
            "<div class='section'>" +
            "<ul>" +
            "<li>确保SQLMap WebUI后端服务已启动</li>" +
            "<li>二进制请求（如图片上传）会显示警告提示</li>" +
            "<li>支持请求去重功能，避免重复提交相同请求</li>" +
            "</ul>" +
            "</div>" +
            
            "</body></html>";
        
        JEditorPane editorPane = createHtmlPane(htmlContent);
        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建开源协议面板
     */
    private JPanel createLicensePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));
        
        JLabel titleLabel = new JLabel("MIT License");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        titleLabel.setBorder(new EmptyBorder(0, 0, 10, 0));
        panel.add(titleLabel, BorderLayout.NORTH);
        
        String licenseText = 
            "MIT License\n\n" +
            "Copyright (c) 2024 GitHubNull\n\n" +
            "Permission is hereby granted, free of charge, to any person obtaining a copy\n" +
            "of this software and associated documentation files (the \"Software\"), to deal\n" +
            "in the Software without restriction, including without limitation the rights\n" +
            "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n" +
            "copies of the Software, and to permit persons to whom the Software is\n" +
            "furnished to do so, subject to the following conditions:\n\n" +
            "The above copyright notice and this permission notice shall be included in all\n" +
            "copies or substantial portions of the Software.\n\n" +
            "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n" +
            "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n" +
            "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n" +
            "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n" +
            "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n" +
            "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n" +
            "SOFTWARE.";
        
        JTextArea textArea = new JTextArea(licenseText);
        textArea.setEditable(false);
        textArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setBackground(new Color(250, 250, 250));
        textArea.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(220, 220, 220)));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建免责声明面板
     */
    private JPanel createDisclaimerPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));
        
        // 警告消息
        JPanel warningPanel = new JPanel(new BorderLayout(10, 0));
        warningPanel.setBackground(new Color(255, 243, 224));
        warningPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(255, 183, 77)),
            new EmptyBorder(10, 15, 10, 15)
        ));
        
        JLabel warningIcon = new JLabel("⚠");
        warningIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 24));
        warningPanel.add(warningIcon, BorderLayout.WEST);
        
        JLabel warningText = new JLabel("本工具仅供合法的安全测试使用，禁止用于非法用途！");
        warningText.setFont(new Font("Microsoft YaHei", Font.BOLD, 13));
        warningPanel.add(warningText, BorderLayout.CENTER);
        
        panel.add(warningPanel, BorderLayout.NORTH);
        
        // 免责声明内容
        String htmlContent = "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', sans-serif; font-size: 12px; line-height: 1.8; }" +
            "h3 { color: #333; margin: 15px 0 8px 0; }" +
            "p { margin: 5px 0; }" +
            "ol, ul { margin: 5px 0 10px 25px; }" +
            "li { margin: 5px 0; }" +
            "strong { color: #333; }" +
            "</style></head><body>" +
            
            "<h3>重要声明</h3>" +
            "<p><strong>SQLMap WebUI Extension</strong> 是一款用于 SQL 注入漏洞检测的安全测试工具。" +
            "本工具仅供合法的安全测试、渗透测试、安全研究和教育目的使用。</p>" +
            
            "<h3>使用条款</h3>" +
            "<p>使用本软件即表示您同意以下条款：</p>" +
            
            "<ol>" +
            "<li><strong>授权使用</strong>: 您必须在获得目标系统所有者明确书面授权后，方可对其进行安全测试。" +
            "未经授权对他人系统进行测试属于违法行为。</li>" +
            
            "<li><strong>合法用途</strong>: 本工具仅可用于以下合法场景：" +
            "<ul>" +
            "<li>经授权的渗透测试项目</li>" +
            "<li>CTF（Capture The Flag）安全竞赛</li>" +
            "<li>安全研究和漏洞分析</li>" +
            "<li>教育培训目的</li>" +
            "<li>自有系统的安全评估</li>" +
            "</ul></li>" +
            
            "<li><strong>禁止滥用</strong>: 严禁将本工具用于任何非法活动，包括但不限于：" +
            "<ul>" +
            "<li>未经授权访问他人计算机系统</li>" +
            "<li>窃取、破坏或篡改他人数据</li>" +
            "<li>进行网络攻击或恶意行为</li>" +
            "<li>违反当地法律法规的任何行为</li>" +
            "</ul></li>" +
            
            "<li><strong>风险承担</strong>: 使用者应充分了解安全测试可能带来的风险。" +
            "使用本工具进行测试时，测试目标系统可能会受到影响，使用者需自行承担所有相关风险。</li>" +
            
            "<li><strong>免责条款</strong>:" +
            "<ul>" +
            "<li>本软件按\"原样\"提供，不提供任何形式的明示或暗示保证</li>" +
            "<li>开发者不对因使用或无法使用本软件而导致的任何直接、间接、偶然、特殊或后果性损害承担责任</li>" +
            "<li>开发者不对用户使用本工具的行为承担任何法律责任</li>" +
            "<li>用户需自行承担使用本软件的全部风险和后果</li>" +
            "</ul></li>" +
            "</ol>" +
            
            "<h3>法律合规</h3>" +
            "<p>请确保您的使用行为符合：</p>" +
            "<ul>" +
            "<li>《中华人民共和国网络安全法》</li>" +
            "<li>《中华人民共和国刑法》相关规定</li>" +
            "<li>所在国家/地区的相关法律法规</li>" +
            "<li>目标系统所在国家/地区的相关法律法规</li>" +
            "</ul>" +
            
            "</body></html>";
        
        JEditorPane editorPane = createHtmlPane(htmlContent);
        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setBorder(new EmptyBorder(10, 0, 0, 0));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建HTML面板
     */
    private JEditorPane createHtmlPane(String htmlContent) {
        JEditorPane editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setEditable(false);
        editorPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        editorPane.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        editorPane.setText(htmlContent);
        editorPane.setCaretPosition(0);
        return editorPane;
    }
    
    /**
     * 显示对话框
     */
    public static void showDialog(Component parent) {
        Window window = SwingUtilities.getWindowAncestor(parent);
        AboutDialog dialog;
        if (window instanceof Frame) {
            dialog = new AboutDialog((Frame) window);
        } else if (window instanceof Dialog) {
            dialog = new AboutDialog((Dialog) window);
        } else {
            dialog = new AboutDialog((Frame) null);
        }
        dialog.setVisible(true);
    }
}
