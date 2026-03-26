package com.sqlmapwebui.burp.panels;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * 命令行执行配置帮助对话框
 * 使用 Tab 分类展示帮助内容
 */
public class CommandExecHelpDialog {

    /**
     * 显示帮助对话框
     */
    public static void showDialog(Component parent) {
        JDialog dialog = new JDialog((Frame) null, "命令行执行配置 - 使用帮助", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(650, 500);
        dialog.setLocationRelativeTo(parent);

        // 创建 Tab 面板
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));

        // Tab 1: 基础配置说明
        JEditorPane basicHelpPane = createHelpPane(createBasicHelpContent());
        JScrollPane basicScrollPane = new JScrollPane(basicHelpPane);
        basicScrollPane.setBorder(new EmptyBorder(10, 10, 10, 10));
        tabbedPane.addTab("基础配置", basicScrollPane);

        // Tab 2: 执行环境说明
        JEditorPane execHelpPane = createHelpPane(createExecHelpContent());
        JScrollPane execScrollPane = new JScrollPane(execHelpPane);
        execScrollPane.setBorder(new EmptyBorder(10, 10, 10, 10));
        tabbedPane.addTab("执行环境", execScrollPane);

        // Tab 3: 标题规则说明
        JEditorPane titleHelpPane = createHelpPane(createTitleHelpContent());
        JScrollPane titleScrollPane = new JScrollPane(titleHelpPane);
        titleScrollPane.setBorder(new EmptyBorder(10, 10, 10, 10));
        tabbedPane.addTab("标题规则", titleScrollPane);

        // Tab 4: 使用流程
        JEditorPane workflowHelpPane = createHelpPane(createWorkflowHelpContent());
        JScrollPane workflowScrollPane = new JScrollPane(workflowHelpPane);
        workflowScrollPane.setBorder(new EmptyBorder(10, 10, 10, 10));
        tabbedPane.addTab("使用流程", workflowScrollPane);

        dialog.add(tabbedPane, BorderLayout.CENTER);

        // 底部按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton closeButton = new JButton("关闭");
        closeButton.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        closeButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    /**
     * 创建帮助文本面板
     */
    private static JEditorPane createHelpPane(String content) {
        JEditorPane pane = new JEditorPane();
        pane.setContentType("text/html");
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        pane.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        pane.setText(content);
        pane.setCaretPosition(0);
        return pane;
    }

    /**
     * 基础配置帮助内容
     */
    private static String createBasicHelpContent() {
        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 5px; line-height: 1.6; }" +
            "h3 { color: #2c3e50; margin: 15px 0 8px 0; border-bottom: 1px solid #bdc3c7; padding-bottom: 3px; }" +
            "ul { margin: 5px 0 10px 20px; padding: 0; }" +
            "li { margin: 3px 0; }" +
            ".code { font-family: 'Consolas', monospace; background: #ecf0f1; padding: 1px 5px; border-radius: 3px; }" +
            ".warning { background: #fff3cd; padding: 8px; border-left: 3px solid #ffc107; margin: 10px 0; }" +
            ".tip { background: #d4edda; padding: 8px; border-left: 3px solid #28a745; margin: 10px 0; }" +
            "</style></head><body>" +

            "<h3>自动复制命令到剪贴板</h3>" +
            "<ul>" +
            "<li><b>勾选</b>：右键点击「复制SQLMap命令」时，命令会自动复制到剪贴板</li>" +
            "<li><b>取消勾选</b>：会弹出预览对话框，您可以编辑命令后再复制</li>" +
            "</ul>" +

            "<h3>临时目录</h3>" +
            "<ul>" +
            "<li>用于存储生成的HTTP请求文件（<span class='code'>sqlmap_request_xxx.txt</span>）</li>" +
            "<li><b>留空</b>：使用系统默认临时目录" +
            "<ul>" +
            "<li>Windows: <span class='code'>%TEMP%</span></li>" +
            "<li>Linux/macOS: <span class='code'>/tmp</span></li>" +
            "</ul></li>" +
            "<li><b>自定义路径</b>：点击「浏览...」选择目录，路径中的空格会自动处理</li>" +
            "</ul>" +

            "<div class='tip'>" +
            "<b>提示：</b>临时文件在使用后可以手动删除，不会自动清理。" +
            "</div>" +

            "</body></html>";
    }

    /**
     * 执行环境帮助内容
     */
    private static String createExecHelpContent() {
        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 5px; line-height: 1.6; }" +
            "h3 { color: #2c3e50; margin: 15px 0 8px 0; border-bottom: 1px solid #bdc3c7; padding-bottom: 3px; }" +
            "h4 { color: #34495e; margin: 10px 0 5px 0; }" +
            "ul { margin: 5px 0 10px 20px; padding: 0; }" +
            "li { margin: 3px 0; }" +
            ".code { font-family: 'Consolas', monospace; background: #ecf0f1; padding: 1px 5px; border-radius: 3px; }" +
            ".required { color: #e74c3c; font-weight: bold; }" +
            ".warning { background: #fff3cd; padding: 8px; border-left: 3px solid #ffc107; margin: 10px 0; }" +
            "</style></head><body>" +

            "<h3>Python路径 <span class='required'>(可选)</span></h3>" +
            "<ul>" +
            "<li>Python解释器的完整路径</li>" +
            "<li><b>留空</b>：使用系统PATH中的Python</li>" +
            "<li>Windows示例: <span class='code'>C:\\Python39\\python.exe</span></li>" +
            "<li>Linux/macOS示例: <span class='code'>/usr/bin/python3</span></li>" +
            "</ul>" +
            "<p>点击「测试」按钮验证Python是否可用并显示版本号。</p>" +

            "<h3>SQLMap路径 <span class='required'>(必填)</span></h3>" +
            "<ul>" +
            "<li>SQLMap脚本 <span class='code'>sqlmap.py</span> 的完整路径</li>" +
            "<li>这是执行扫描的必要配置</li>" +
            "<li>Windows示例: <span class='code'>C:\\sqlmap\\sqlmap.py</span></li>" +
            "<li>Linux/macOS示例: <span class='code'>/opt/sqlmap/sqlmap.py</span></li>" +
            "</ul>" +
            "<p>点击「测试」按钮验证SQLMap脚本是否有效。</p>" +

            "<h3>终端类型</h3>" +
            "<ul>" +
            "<li><span class='code'>自动检测</span>：根据操作系统自动选择合适的终端</li>" +
            "<li><b>Windows</b>: CMD 或 PowerShell</li>" +
            "<li><b>Linux</b>: GNOME Terminal 或 XTerm</li>" +
            "<li><b>macOS</b>: Terminal.app 或 iTerm2</li>" +
            "</ul>" +

            "<h3>执行后保持终端打开</h3>" +
            "<ul>" +
            "<li><b>勾选</b>：SQLMap执行完毕后终端窗口保持打开</li>" +
            "<li><b>取消勾选</b>：执行完毕后终端窗口自动关闭</li>" +
            "</ul>" +

            "<div class='warning'>" +
            "<b>注意：</b>确保已正确安装Python和SQLMap，否则命令执行会失败。" +
            "</div>" +

            "</body></html>";
    }

    /**
     * 标题规则帮助内容
     */
    private static String createTitleHelpContent() {
        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 5px; line-height: 1.6; }" +
            "h3 { color: #2c3e50; margin: 15px 0 8px 0; border-bottom: 1px solid #bdc3c7; padding-bottom: 3px; }" +
            "h4 { color: #34495e; margin: 10px 0 5px 0; }" +
            "ul { margin: 5px 0 10px 20px; padding: 0; }" +
            "li { margin: 3px 0; }" +
            ".code { font-family: 'Consolas', monospace; background: #ecf0f1; padding: 1px 5px; border-radius: 3px; }" +
            ".tip { background: #d4edda; padding: 8px; border-left: 3px solid #28a745; margin: 10px 0; }" +
            "table { border-collapse: collapse; width: 100%; margin: 10px 0; }" +
            "th, td { border: 1px solid #ddd; padding: 6px; text-align: left; }" +
            "th { background: #f5f5f5; }" +
            "</style></head><body>" +

            "<h3>标题提取规则</h3>" +
            "<p>标题规则用于为终端窗口设置有意义的标题，便于区分多个扫描任务。</p>" +

            "<h4>规则优先级</h4>" +
            "<ul>" +
            "<li>按优先级数字从小到大依次匹配（数字越小优先级越高）</li>" +
            "<li>第一个成功提取标题的规则生效</li>" +
            "<li>默认规则（URL路径）不可删除，作为最终兜底</li>" +
            "</ul>" +

            "<h4>提取方式</h4>" +
            "<table>" +
            "<tr><th>方式</th><th>说明</th><th>示例</th></tr>" +
            "<tr><td>URL路径</td><td>从URL路径提取最后一部分</td><td><span class='code'>/api/user/login</span> → login</td></tr>" +
            "<tr><td>URL路径子串</td><td>提取路径的指定范围</td><td>第2到第3段 → user</td></tr>" +
            "<tr><td>固定值</td><td>使用预设的固定标题</td><td>SQLMap-Test</td></tr>" +
            "<tr><td>正则表达式</td><td>使用正则匹配URL或请求体</td><td><span class='code'>id=(\\d+)</span> → 123</td></tr>" +
            "<tr><td>JSON Path</td><td>从JSON请求体提取</td><td><span class='code'>$.action</span> → login</td></tr>" +
            "<tr><td>XPath</td><td>从XML请求体提取</td><td><span class='code'>//method</span> → POST</td></tr>" +
            "<tr><td>表单字段</td><td>从表单数据提取</td><td>action字段的值</td></tr>" +
            "</table>" +

            "<h4>全局配置</h4>" +
            "<ul>" +
            "<li><b>回退标题</b>：所有规则都匹配失败时使用的默认标题</li>" +
            "<li><b>最大长度</b>：标题的最大字符数，超长会截断并添加省略号前缀</li>" +
            "</ul>" +

            "<div class='tip'>" +
            "<b>提示：</b>可以使用「测试」功能验证规则是否正确提取预期的标题。" +
            "</div>" +

            "</body></html>";
    }

    /**
     * 使用流程帮助内容
     */
    private static String createWorkflowHelpContent() {
        return "<html><head><style>" +
            "body { font-family: 'Microsoft YaHei', 'SimHei', sans-serif; font-size: 12px; margin: 5px; line-height: 1.6; }" +
            "h3 { color: #2c3e50; margin: 15px 0 8px 0; border-bottom: 1px solid #bdc3c7; padding-bottom: 3px; }" +
            "ol { margin: 5px 0 10px 20px; padding: 0; }" +
            "li { margin: 5px 0; }" +
            ".code { font-family: 'Consolas', monospace; background: #ecf0f1; padding: 1px 5px; border-radius: 3px; }" +
            ".tip { background: #d4edda; padding: 8px; border-left: 3px solid #28a745; margin: 10px 0; }" +
            ".warning { background: #fff3cd; padding: 8px; border-left: 3px solid #ffc107; margin: 10px 0; }" +
            "</style></head><body>" +

            "<h3>方式一：复制命令到剪贴板</h3>" +
            "<ol>" +
            "<li>在Burp中选择要测试的HTTP请求</li>" +
            "<li>右键点击，选择 <span class='code'>复制SQLMap命令</span></li>" +
            "<li>如果配置了「自动复制」，命令已复制到剪贴板</li>" +
            "<li>打开终端，粘贴命令并执行</li>" +
            "</ol>" +

            "<h3>方式二：直接在终端执行</h3>" +
            "<ol>" +
            "<li>确保已配置Python路径和SQLMap路径</li>" +
            "<li>在Burp中选择要测试的HTTP请求</li>" +
            "<li>右键点击，选择 <span class='code'>执行SQLMap扫描</span></li>" +
            "<li>系统会自动打开终端窗口并执行SQLMap</li>" +
            "<li>终端窗口标题会显示提取的标题</li>" +
            "</ol>" +

            "<h3>批量执行</h3>" +
            "<ol>" +
            "<li>在Burp中多选多个HTTP请求</li>" +
            "<li>右键点击，选择 <span class='code'>执行SQLMap扫描</span></li>" +
            "<li>每个请求会在独立的终端窗口中执行</li>" +
            "<li>窗口标题会添加序号后缀区分（如 <span class='code'>login-1</span>、<span class='code'>login-2</span>）</li>" +
            "</ol>" +

            "<div class='tip'>" +
            "<b>提示：</b>使用「直接执行」功能时，SQLMap输出信息会显示在终端窗口中，可以实时查看扫描进度。" +
            "</div>" +

            "<div class='warning'>" +
            "<b>注意：</b>此功能仅在授权的安全测试环境中使用，请遵守相关法律法规。" +
            "</div>" +

            "</body></html>";
    }
}
