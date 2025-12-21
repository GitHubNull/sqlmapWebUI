package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.PresetConfig;
import com.sqlmapwebui.burp.PresetConfigDatabase;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

/**
 * 配置导入导出辅助类
 * 支持YAML和SQL格式的导入导出
 */
public class ConfigImportExportHelper {
    
    private final Component parent;
    private final PresetConfigDatabase database;
    private final Consumer<String> logAppender;
    
    // 允许的SQL操作类型（白名单）
    private static final String[] ALLOWED_SQL_OPERATIONS = {"INSERT", "CREATE TABLE"};
    
    public ConfigImportExportHelper(Component parent, PresetConfigDatabase database, Consumer<String> logAppender) {
        this.parent = parent;
        this.database = database;
        this.logAppender = logAppender;
    }
    
    /**
     * 显示导入对话框
     * @return 导入的配置数量，失败返回-1
     */
    public int showImportDialog() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入配置");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
            "YAML/SQL 文件 (*.yaml, *.yml, *.sql)", "yaml", "yml", "sql"));
        fileChooser.setAcceptAllFileFilterUsed(false);
        
        if (fileChooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            String fileName = file.getName().toLowerCase();
            
            try {
                int imported = 0;
                if (fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
                    imported = importFromYaml(file);
                } else if (fileName.endsWith(".sql")) {
                    imported = importFromSql(file);
                } else {
                    HtmlMessageDialog.showWarning(parent, "不支持的格式", 
                        "请选择 .yaml, .yml 或 .sql 文件");
                    return -1;
                }
                
                appendLog("[+] 导入完成，成功导入 " + imported + " 条配置");
                HtmlMessageDialog.showInfo(parent, "导入成功", 
                    "成功导入 <b>" + imported + "</b> 条配置");
                return imported;
                
            } catch (Exception e) {
                appendLog("[-] 导入失败: " + e.getMessage());
                HtmlMessageDialog.showError(parent, "导入失败", e.getMessage());
                return -1;
            }
        }
        return -1;
    }
    
    /**
     * 显示导出对话框
     * @return 是否成功导出
     */
    public boolean showExportDialog() {
        List<PresetConfig> configs = database.findAll();
        if (configs.isEmpty()) {
            HtmlMessageDialog.showWarning(parent, "无数据", "没有可导出的配置数据");
            return false;
        }
        
        // 选择导出格式
        String[] options = {"YAML 格式", "SQL 格式", "取消"};
        int choice = JOptionPane.showOptionDialog(parent,
            "请选择导出格式",
            "导出配置",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]);
        
        if (choice == 2 || choice == JOptionPane.CLOSED_OPTION) {
            return false;
        }
        
        String extension = (choice == 0) ? "yaml" : "sql";
        String description = (choice == 0) ? "YAML 文件 (*.yaml)" : "SQL 文件 (*.sql)";
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出配置");
        fileChooser.setSelectedFile(new File("preset_configs." + extension));
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
            description, extension));
        
        if (fileChooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
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
                HtmlMessageDialog.showInfo(parent, "导出成功", 
                    "<p>已导出 <b>" + configs.size() + "</b> 条配置</p>" +
                    "<p>文件: " + file.getName() + "</p>");
                return true;
                
            } catch (Exception e) {
                appendLog("[-] 导出失败: " + e.getMessage());
                HtmlMessageDialog.showError(parent, "导出失败", e.getMessage());
                return false;
            }
        }
        return false;
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
            int valuesStart = sql.toUpperCase().indexOf("VALUES");
            if (valuesStart < 0) return null;
            
            String valuesPart = sql.substring(valuesStart + 6).trim();
            valuesPart = valuesPart.replaceAll("^\\(", "").replaceAll("\\);?$", "");
            
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
    
    private void appendLog(String message) {
        if (logAppender != null) {
            logAppender.accept(message);
        }
    }
}
