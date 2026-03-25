package com.sqlmapwebui.burp.util;

import com.sqlmapwebui.burp.ConfigManager.TerminalType;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.CompletableFuture;

/**
 * 命令执行工具类
 * 负责执行终端命令和剪贴板操作
 */
public final class CommandExecutor {

    private CommandExecutor() {
        throw new AssertionError("CommandExecutor cannot be instantiated");
    }

    // ==================== 剪贴板操作 ====================

    /**
     * 复制文本到系统剪贴板
     *
     * @param text 要复制的文本
     * @return 是否成功
     */
    public static boolean copyToClipboard(String text) {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection selection = new StringSelection(text);
            clipboard.setContents(selection, null);
            return true;
        } catch (Exception e) {
            System.err.println("Failed to copy to clipboard: " + e.getMessage());
            return false;
        }
    }

    /**
     * 从系统剪贴板获取文本
     *
     * @return 剪贴板文本，如果失败返回 null
     */
    public static String getFromClipboard() {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            return clipboard.getContents(null)
                    .getTransferData(java.awt.datatransfer.DataFlavor.stringFlavor)
                    .toString();
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== 终端命令执行 ====================

    /**
     * 执行结果类
     */
    public static class ExecutionResult {
        private final boolean success;
        private final String message;
        private final Exception exception;

        private ExecutionResult(boolean success, String message, Exception exception) {
            this.success = success;
            this.message = message;
            this.exception = exception;
        }

        public static ExecutionResult success(String message) {
            return new ExecutionResult(true, message, null);
        }

        public static ExecutionResult failure(String message, Exception exception) {
            return new ExecutionResult(false, message, exception);
        }

        public boolean isSuccess() {
            return success;
        }

        public String getMessage() {
            return message;
        }

        public Exception getException() {
            return exception;
        }
    }

    /**
     * 在新终端窗口中执行命令
     *
     * @param command 要执行的命令
     * @param terminalType 终端类型
     * @param keepTerminal 执行后是否保持终端打开
     * @return 执行结果
     */
    public static ExecutionResult executeInTerminal(
            String command,
            TerminalType terminalType,
            boolean keepTerminal) {

        try {
            // 构建完整的终端命令
            String terminalCommand = SqlCommandBuilder.buildTerminalCommand(
                    command, terminalType, keepTerminal);

            // 获取操作系统类型
            SqlCommandBuilder.OsType osType = SqlCommandBuilder.detectOs();

            ProcessBuilder processBuilder;
            if (osType == SqlCommandBuilder.OsType.WINDOWS) {
                // Windows 使用 cmd.exe 执行
                processBuilder = new ProcessBuilder("cmd.exe", "/c", terminalCommand);
            } else {
                // Unix/Linux/macOS 使用 sh 执行
                processBuilder = new ProcessBuilder("sh", "-c", terminalCommand);
            }

            // 设置工作目录为用户主目录
            processBuilder.directory(new java.io.File(System.getProperty("user.home")));

            // 启动进程
            Process process = processBuilder.start();

            // 不等待进程完成，因为终端会独立运行
            // 但需要验证进程是否成功启动

            return ExecutionResult.success("命令已在终端中启动");

        } catch (IOException e) {
            return ExecutionResult.failure("启动终端失败: " + e.getMessage(), e);
        }
    }

    /**
     * 异步在新终端窗口中执行命令
     *
     * @param command 要执行的命令
     * @param terminalType 终端类型
     * @param keepTerminal 执行后是否保持终端打开
     * @return 异步执行结果
     */
    public static CompletableFuture<ExecutionResult> executeInTerminalAsync(
            String command,
            TerminalType terminalType,
            boolean keepTerminal) {

        return CompletableFuture.supplyAsync(() ->
                executeInTerminal(command, terminalType, keepTerminal));
    }

    /**
     * 执行简单命令并获取输出（用于测试配置）
     *
     * @param command 要执行的命令
     * @param timeoutMs 超时时间（毫秒）
     * @return 命令输出
     */
    public static ExecutionResult executeCommand(String command, long timeoutMs) {
        try {
            SqlCommandBuilder.OsType osType = SqlCommandBuilder.detectOs();

            ProcessBuilder processBuilder;
            if (osType == SqlCommandBuilder.OsType.WINDOWS) {
                processBuilder = new ProcessBuilder("cmd.exe", "/c", command);
            } else {
                processBuilder = new ProcessBuilder("sh", "-c", command);
            }

            // 合并 stderr 到 stdout，防止因 stderr 缓冲区满导致进程阻塞（经典死锁问题）
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            // 读取输出
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // 等待进程完成
            boolean finished = process.waitFor(timeoutMs / 1000, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return ExecutionResult.failure("命令执行超时", null);
            }

            int exitCode = process.exitValue();
            if (exitCode == 0) {
                return ExecutionResult.success(output.toString().trim());
            } else {
                return ExecutionResult.failure(
                        "命令执行失败，退出码: " + exitCode + "\n输出: " + output, null);
            }

        } catch (Exception e) {
            return ExecutionResult.failure("命令执行异常: " + e.getMessage(), e);
        }
    }

    // ==================== 配置验证 ====================

    /**
     * 验证 Python 路径配置
     *
     * @param pythonPath Python 路径（空表示使用系统默认）
     * @return 验证结果
     */
    public static ExecutionResult validatePythonPath(String pythonPath) {
        String command;
        if (pythonPath == null || pythonPath.trim().isEmpty()) {
            // 使用系统默认 Python
            SqlCommandBuilder.OsType osType = SqlCommandBuilder.detectOs();
            command = (osType == SqlCommandBuilder.OsType.WINDOWS) ? "python --version" : "python3 --version";
        } else {
            command = SqlCommandBuilder.escapePath(pythonPath) + " --version";
        }

        return executeCommand(command, 5000);
    }

    /**
     * 验证 SQLMap 路径配置
     *
     * @param pythonPath Python 路径
     * @param sqlmapPath SQLMap 脚本路径
     * @return 验证结果
     */
    public static ExecutionResult validateSqlmapPath(String pythonPath, String sqlmapPath) {
        if (sqlmapPath == null || sqlmapPath.trim().isEmpty()) {
            return ExecutionResult.failure("SQLMap 路径未配置", null);
        }

        // 检查文件是否存在
        java.io.File sqlmapFile = new java.io.File(sqlmapPath);
        if (!sqlmapFile.exists()) {
            return ExecutionResult.failure("SQLMap 文件不存在: " + sqlmapPath, null);
        }

        // 尝试运行 sqlmap --version --batch（--batch 防止交互式询问）
        String command = SqlCommandBuilder.buildSqlMapCommand(pythonPath, sqlmapPath, "", "--version --batch");
        // 移除空的请求文件参数
        command = command.replace(" -r ", " ").replace("  ", " ").trim();

        return executeCommand(command, 10000);
    }

    /**
     * 验证终端配置
     *
     * @param terminalType 终端类型
     * @return 验证结果
     */
    public static ExecutionResult validateTerminal(TerminalType terminalType) {
        TerminalType effectiveType = SqlCommandBuilder.getEffectiveTerminalType(terminalType);

        String command;
        switch (effectiveType) {
            case CMD:
                command = "cmd /c echo Terminal OK";
                break;
            case POWERSHELL:
                command = "powershell -Command echo 'Terminal OK'";
                break;
            case GNOME_TERMINAL:
                command = "which gnome-terminal";
                break;
            case XTERM:
                command = "which xterm";
                break;
            case TERMINAL_APP:
            case ITERM:
                // macOS 终端总是可用
                return ExecutionResult.success("macOS 终端已就绪");
            default:
                command = "echo Terminal OK";
        }

        return executeCommand(command, 5000);
    }
}
