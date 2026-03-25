package com.sqlmapwebui.burp.util;

import com.sqlmapwebui.burp.ConfigManager.TerminalType;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * SQLMap 命令行构建器
 * 负责构建跨平台的 SQLMap 执行命令
 *
 * 功能：
 * - 检测操作系统类型
 * - 生成 HTTP 请求临时文件
 * - 构建不同平台的终端执行命令
 */
public final class SqlCommandBuilder {

    private SqlCommandBuilder() {
        throw new AssertionError("SqlCommandBuilder cannot be instantiated");
    }

    // ==================== 操作系统检测 ====================

    /**
     * 操作系统类型枚举
     */
    public enum OsType {
        WINDOWS,
        MACOS,
        LINUX,
        UNKNOWN
    }

    /**
     * 检测当前操作系统类型
     */
    public static OsType detectOs() {
        String osName = System.getProperty("os.name", "").toLowerCase(Locale.ENGLISH);
        if (osName.contains("win")) {
            return OsType.WINDOWS;
        } else if (osName.contains("mac")) {
            return OsType.MACOS;
        } else if (osName.contains("nix") || osName.contains("nux") || osName.contains("aix")) {
            return OsType.LINUX;
        }
        return OsType.UNKNOWN;
    }

    /**
     * 根据配置获取实际使用的终端类型
     * 如果配置为 AUTO， 则自动检测
     */
    public static TerminalType getEffectiveTerminalType(TerminalType configuredType) {
        if (configuredType == TerminalType.AUTO) {
            return getDefaultTerminalForOs();
        }
        return configuredType;
    }

    /**
     * 根据操作系统获取默认终端类型
     */
    public static TerminalType getDefaultTerminalForOs() {
        OsType os = detectOs();
        switch (os) {
            case WINDOWS:
                return TerminalType.CMD;
            case MACOS:
                return TerminalType.TERMINAL_APP;
            case LINUX:
                return TerminalType.GNOME_TERMINAL;
            default:
                return TerminalType.CMD;
        }
    }

    // ==================== HTTP 请求文件生成 ====================

    /**
     * 生成 HTTP 请求临时文件
     *
     * @param httpRequest 原始 HTTP 请求内容
     * @param tempDir 临时目录，如果为空则使用系统默认临时目录
     * @return 生成的临时文件路径
     * @throws IOException 文件写入失败时抛出
     */
    public static String generateRequestFile(String httpRequest, String tempDir) throws IOException {
        String prefix = "sqlmap_request_";
        String suffix = ".txt";

        Path tempPath;
        if (tempDir != null && !tempDir.trim().isEmpty()) {
            // 使用指定的临时目录
            File dir = new File(tempDir);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            tempPath = Files.createTempFile(dir.toPath(), prefix, suffix);
        } else {
            // 使用系统默认临时目录
            tempPath = Files.createTempFile(prefix, suffix);
        }

        // 写入 HTTP 请求内容
        Files.writeString(tempPath, httpRequest, StandardCharsets.UTF_8);

        return tempPath.toAbsolutePath().toString();
    }

    /**
     * 删除临时请求文件
     */
    public static void deleteTempFile(String filePath) {
        if (filePath != null) {
            try {
                Files.deleteIfExists(Path.of(filePath));
            } catch (IOException ignored) {
                // 忽略删除失败
            }
        }
    }

    // ==================== SQLMap 命令构建 ====================

    /**
     * 构建 SQLMap 命令行
     *
     * @param pythonPath Python 解释器路径（空则使用系统 PATH 中的 python）
     * @param sqlmapPath SQLMap 脚本路径
     * @param requestFilePath HTTP 请求文件路径
     * @param additionalParams 额外的 SQLMap 参数（可选）
     * @return SQLMap 命令行字符串
     */
    public static String buildSqlMapCommand(
            String pythonPath,
            String sqlmapPath,
            String requestFilePath,
            String additionalParams) {

        StringBuilder cmd = new StringBuilder();

        // Python 解释器
        if (pythonPath != null && !pythonPath.trim().isEmpty()) {
            cmd.append(escapePath(pythonPath));
        } else {
            OsType os = detectOs();
            if (os == OsType.WINDOWS) {
                cmd.append("python");
            } else {
                cmd.append("python3");
            }
        }

        // SQLMap 脚本路径（非空时添加）
        if (sqlmapPath != null && !sqlmapPath.trim().isEmpty()) {
            cmd.append(" ");
            cmd.append(escapePath(sqlmapPath));
        }

        // 请求文件参数
        cmd.append(" -r ").append(escapePath(requestFilePath));

        // 额外参数
        if (additionalParams != null && !additionalParams.trim().isEmpty()) {
            cmd.append(" ").append(additionalParams.trim());
        }

        return cmd.toString();
    }

    // ==================== 终端命令构建 ====================

    /**
     * 构建完整的终端执行命令（使用默认标题 "SQLMap"）
     *
     * @param sqlmapCommand SQLMap 命令行
     * @param terminalType 终端类型
     * @param keepTerminal 执行后是否保持终端打开
     * @return 完整的终端执行命令
     */
    public static String buildTerminalCommand(
            String sqlmapCommand,
            TerminalType terminalType,
            boolean keepTerminal) {
        return buildTerminalCommand(sqlmapCommand, terminalType, keepTerminal, "SQLMap");
    }

    /**
     * 构建完整的终端执行命令（支持自定义标题）
     *
     * @param sqlmapCommand SQLMap 命令行
     * @param terminalType 终端类型
     * @param keepTerminal 执行后是否保持终端打开
     * @param title 终端窗口标题
     * @return 完整的终端执行命令
     */
    public static String buildTerminalCommand(
            String sqlmapCommand,
            TerminalType terminalType,
            boolean keepTerminal,
            String title) {

        TerminalType effectiveType = getEffectiveTerminalType(terminalType);
        
        // 清理标题
        String safeTitle = sanitizeTitleForTerminal(title != null ? title : "SQLMap");

        switch (effectiveType) {
            case CMD:
                return buildCmdCommand(sqlmapCommand, keepTerminal, safeTitle);
            case POWERSHELL:
                return buildPowerShellCommand(sqlmapCommand, keepTerminal, safeTitle);
            case GNOME_TERMINAL:
                return buildGnomeTerminalCommand(sqlmapCommand, keepTerminal, safeTitle);
            case XTERM:
                return buildXtermCommand(sqlmapCommand, keepTerminal, safeTitle);
            case TERMINAL_APP:
                return buildMacTerminalCommand(sqlmapCommand, keepTerminal, safeTitle);
            case ITERM:
                return buildITermCommand(sqlmapCommand, keepTerminal, safeTitle);
            default:
                return buildCmdCommand(sqlmapCommand, keepTerminal, safeTitle);
        }
    }
    
    /**
     * 清理标题用于终端命令
     * 移除或转义可能导致命令解析问题的字符
     */
    private static String sanitizeTitleForTerminal(String title) {
        if (title == null || title.isEmpty()) {
            return "SQLMap";
        }
        
        // 移除控制字符和引号
        String sanitized = title
            .replace("\"", "'")  // 替换双引号为单引号
            .replace("\n", " ")  // 替换换行为空格
            .replace("\r", "")   // 移除回车
            .replace("\t", " ")  // 替换制表符为空格
            .replaceAll("\\s+", " ")  // 多个空格合并为一个
            .trim();
        
        // 限制长度
        if (sanitized.length() > 50) {
            sanitized = sanitized.substring(0, 47) + "...";
        }
        
        return sanitized.isEmpty() ? "SQLMap" : sanitized;
    }

    /**
     * 构建 Windows CMD 命令
     * 使用 start "" 确保弹出新的可见 CMD 窗口
     */
    private static String buildCmdCommand(String sqlmapCommand, boolean keepTerminal, String title) {
        if (keepTerminal) {
            // start "title" cmd /k <command> — 打开新窗口，执行后保持打开
            return "start \"" + title + "\" cmd /k " + sqlmapCommand;
        } else {
            // start "title" cmd /c <command> — 打开新窗口，执行完后自动关闭
            return "start \"" + title + "\" cmd /c " + sqlmapCommand;
        }
    }

    /**
     * 构建 Windows PowerShell 命令
     * 使用 start "" 确保弹出新的可见 PowerShell 窗口
     */
    private static String buildPowerShellCommand(String sqlmapCommand, boolean keepTerminal, String title) {
        if (keepTerminal) {
            // 打开新 PowerShell 窗口，执行后保持打开
            return "start \"" + title + "\" powershell -NoExit -Command " + sqlmapCommand;
        } else {
            return "start \"" + title + "\" powershell -Command " + sqlmapCommand;
        }
    }

    /**
     * 构建 Linux GNOME Terminal 命令
     */
    private static String buildGnomeTerminalCommand(String sqlmapCommand, boolean keepTerminal, String title) {
        // GNOME Terminal 执行后默认保持窗口
        // 使用 --title 设置窗口标题
        // 使用 -- bash -c "command; exec bash" 可以在命令完成后进入交互式 shell
        if (keepTerminal) {
            return "gnome-terminal --title=\"" + title + "\" -- bash -c \"" + sqlmapCommand + "; exec bash\"";
        } else {
            return "gnome-terminal --title=\"" + title + "\" -- " + sqlmapCommand;
        }
    }

    /**
     * 构建 Linux xterm 命令
     */
    private static String buildXtermCommand(String sqlmapCommand, boolean keepTerminal, String title) {
        // xterm 使用 -hold 参数保持窗口
        // 使用 -T 设置窗口标题
        if (keepTerminal) {
            return "xterm -T \"" + title + "\" -hold -e " + sqlmapCommand;
        } else {
            return "xterm -T \"" + title + "\" -e " + sqlmapCommand;
        }
    }

    /**
     * 构建 macOS Terminal.app 命令
     */
    private static String buildMacTerminalCommand(String sqlmapCommand, boolean keepTerminal, String title) {
        // macOS Terminal 使用 osascript 执行
        // Terminal.app 默认保持窗口打开
        // 使用 AppleScript 设置自定义标题
        String escapedCommand = sqlmapCommand.replace("\"", "\\\"");
        String escapedTitle = title.replace("\"", "\\\"");
        
        // AppleScript: 打开新窗口执行命令，然后设置窗口标题
        String script = String.format(
            "tell application \"Terminal\"\n" +
            "    set newTab to do script \"%s\"\n" +
            "    set custom title of newTab to \"%s\"\n" +
            "end tell",
            escapedCommand, escapedTitle
        );
        return "osascript -e '" + script + "'";
    }

    /**
     * 构建 macOS iTerm2 命令
     */
    private static String buildITermCommand(String sqlmapCommand, boolean keepTerminal, String title) {
        // iTerm2 使用 osascript 执行
        // 使用 AppleScript 设置窗口标题
        String escapedCommand = sqlmapCommand.replace("\"", "\\\"");
        String escapedTitle = title.replace("\"", "\\\"");
        
        // AppleScript: 创建新窗口并设置标题
        String script = String.format(
            "tell application \"iTerm\"\n" +
            "    tell current window\n" +
            "        create tab with default profile command \"%s\"\n" +
            "        set name to \"%s\"\n" +
            "    end tell\n" +
            "end tell",
            escapedCommand, escapedTitle
        );
        return "osascript -e '" + script + "'";
    }

    // ==================== 路径转义 ====================

    /**
     * 转义文件路径（处理空格和特殊字符）
     */
    public static String escapePath(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }

        OsType os = detectOs();

        if (os == OsType.WINDOWS) {
            // Windows: 如果路径包含空格，用双引号包裹
            if (path.contains(" ") || path.contains("&") || path.contains("|")) {
                return "\"" + path + "\"";
            }
            return path;
        } else {
            // Unix/Linux/macOS: 转义空格和特殊字符
            return path.replace(" ", "\\ ")
                      .replace("(", "\\(")
                      .replace(")", "\\)")
                      .replace("&", "\\&")
                      .replace("|", "\\|");
        }
    }

    /**
     * 构建用于剪贴板复制的命令
     * 返回可以直接复制到终端执行的命令字符串
     *
     * @param pythonPath Python 路径
     * @param sqlmapPath SQLMap 路径
     * @param requestFilePath 请求文件路径
     * @param additionalParams 额外参数
     * @return 完整的命令字符串
     */
    public static String buildCopyableCommand(
            String pythonPath,
            String sqlmapPath,
            String requestFilePath,
            String additionalParams) {

        return buildSqlMapCommand(pythonPath, sqlmapPath, requestFilePath, additionalParams);
    }

    /**
     * 获取终端类型的显示名称
     */
    public static String getTerminalDisplayName(TerminalType type) {
        if (type == TerminalType.AUTO) {
            return "Auto (" + getTerminalDisplayName(getDefaultTerminalForOs()) + ")";
        }

        switch (type) {
            case CMD:
                return "Windows CMD";
            case POWERSHELL:
                return "Windows PowerShell";
            case GNOME_TERMINAL:
                return "GNOME Terminal (Linux)";
            case XTERM:
                return "XTerm (Linux)";
            case TERMINAL_APP:
                return "Terminal.app (macOS)";
            case ITERM:
                return "iTerm2 (macOS)";
            default:
                return type.name();
        }
    }

    /**
     * 获取所有可用的终端类型选项
     */
    public static List<TerminalOption> getTerminalOptions() {
        List<TerminalOption> options = new ArrayList<>();
        options.add(new TerminalOption(TerminalType.AUTO, "Auto"));

        OsType os = detectOs();
        if (os == OsType.WINDOWS) {
            options.add(new TerminalOption(TerminalType.CMD, "CMD"));
            options.add(new TerminalOption(TerminalType.POWERSHELL, "PowerShell"));
        } else if (os == OsType.MACOS) {
            options.add(new TerminalOption(TerminalType.TERMINAL_APP, "Terminal.app"));
            options.add(new TerminalOption(TerminalType.ITERM, "iTerm2"));
        } else if (os == OsType.LINUX) {
            options.add(new TerminalOption(TerminalType.GNOME_TERMINAL, "GNOME Terminal"));
            options.add(new TerminalOption(TerminalType.XTERM, "XTerm"));
        } else {
            // 未知系统显示所有选项
            options.add(new TerminalOption(TerminalType.CMD, "CMD"));
            options.add(new TerminalOption(TerminalType.POWERSHELL, "PowerShell"));
            options.add(new TerminalOption(TerminalType.GNOME_TERMINAL, "GNOME Terminal"));
            options.add(new TerminalOption(TerminalType.XTERM, "XTerm"));
            options.add(new TerminalOption(TerminalType.TERMINAL_APP, "Terminal.app"));
            options.add(new TerminalOption(TerminalType.ITERM, "iTerm2"));
        }

        return options;
    }

    /**
     * 终端选项包装类
     */
    public static class TerminalOption {
        private final TerminalType type;
        private final String displayName;

        public TerminalOption(TerminalType type, String displayName) {
            this.type = type;
            this.displayName = displayName;
        }

        public TerminalType getType() {
            return type;
        }

        public String getDisplayName() {
            return displayName;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }
}
