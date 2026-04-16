package com.sqlmapwebui.burp.config;

import java.io.File;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * SQLite数据库管理类
 * 用于存储和管理常用配置
 */
public class PresetConfigDatabase {
    
    private static final String DB_FILE_NAME = "sqlmap-webui-presets.db";
    private static final String TABLE_NAME = "preset_configs";
    private static final String COMMAND_EXEC_TABLE = "command_exec_configs";
    
    /** SQLite JDBC 驱动是否已加载 */
    private static boolean driverLoaded = false;
    
    private final String dbPath;
    private final Consumer<String> logAppender;
    
    public PresetConfigDatabase(Consumer<String> logAppender) {
        this.logAppender = logAppender;
        // 获取Burp Suite运行目录
        String userDir = System.getProperty("user.dir");
        this.dbPath = new File(userDir, DB_FILE_NAME).getAbsolutePath();
        
        // 确保驱动已加载
        loadDriver();
        initializeDatabase();
    }
    
    /**
     * 显式加载 SQLite JDBC 驱动
     * 在 Burp Suite 环境中，SPI 机制可能无法自动发现驱动
     */
    private synchronized void loadDriver() {
        if (driverLoaded) {
            return;
        }
        
        try {
            // 显式加载 SQLite JDBC 驱动类
            Class.forName("org.sqlite.JDBC");
            driverLoaded = true;
            log("[+] SQLite JDBC 驱动加载成功");
        } catch (ClassNotFoundException e) {
            log("[-] SQLite JDBC 驱动加载失败: " + e.getMessage());
            log("[-] 请确保插件 JAR 包含 sqlite-jdbc 依赖");
        }
    }
    
    /**
     * 初始化数据库
     */
    private void initializeDatabase() {
        // 创建常用配置表
        String createPresetTableSQL = 
            "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "name TEXT NOT NULL, " +
            "description TEXT, " +
            "parameter_string TEXT NOT NULL, " +
            "created_time TEXT NOT NULL, " +
            "modified_time TEXT NOT NULL" +
            ")";

        // 创建命令行执行配置表
        String createCommandExecTableSQL = 
            "CREATE TABLE IF NOT EXISTS " + COMMAND_EXEC_TABLE + " (" +
            "id INTEGER PRIMARY KEY CHECK (id = 1), " +
            "auto_copy INTEGER NOT NULL DEFAULT 1, " +
            "temp_dir TEXT DEFAULT '', " +
            "script_temp_dir TEXT DEFAULT '', " +
            "python_path TEXT DEFAULT '', " +
            "sqlmap_path TEXT DEFAULT '', " +
            "terminal_type TEXT DEFAULT 'AUTO', " +
            "keep_terminal INTEGER NOT NULL DEFAULT 1, " +
            "title_rules TEXT DEFAULT '[]', " +
            "title_fallback TEXT DEFAULT 'SQLMap', " +
            "title_max_length INTEGER DEFAULT 50" +
            ")";

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(createPresetTableSQL);
            stmt.execute(createCommandExecTableSQL);
            
            // 检查并添加 script_temp_dir 列（如果不存在）
            try {
                stmt.execute("ALTER TABLE " + COMMAND_EXEC_TABLE + " ADD COLUMN script_temp_dir TEXT DEFAULT ''");
            } catch (SQLException e) {
                // 列已存在，忽略错误
            }
            
            log("[+] 常用配置数据库初始化成功: " + dbPath);
        } catch (SQLException e) {
            log("[-] 数据库初始化失败: " + e.getMessage());
        }
    }
    
    /**
     * 获取数据库连接
     */
    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }
    
    /**
     * 添加新配置
     */
    public boolean insert(PresetConfig config) {
        // 检查同名配置
        if (existsByName(config.getName())) {
            log("[-] 添加配置失败: 配置名称 '" + config.getName() + "' 已存在");
            return false;
        }
        
        String sql = "INSERT INTO " + TABLE_NAME + 
            " (name, description, parameter_string, created_time, modified_time) VALUES (?, ?, ?, ?, ?)";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, config.getName());
            pstmt.setString(2, config.getDescription());
            pstmt.setString(3, config.getParameterString());
            pstmt.setString(4, config.getFormattedCreatedTime());
            pstmt.setString(5, config.getFormattedModifiedTime());
            
            int affected = pstmt.executeUpdate();
            
            if (affected > 0) {
                // 使用 SQLite 特有的方式获取最后插入的 ID
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT last_insert_rowid()")) {
                    if (rs.next()) {
                        config.setId(rs.getLong(1));
                    }
                }
                log("[+] 配置已添加: " + config.getName());
                return true;
            }
        } catch (SQLException e) {
            log("[-] 添加配置失败: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * 更新配置
     */
    public boolean update(PresetConfig config) {
        // 检查同名配置（排除自己）
        if (existsByNameExcludeId(config.getName(), config.getId())) {
            log("[-] 更新配置失败: 配置名称 '" + config.getName() + "' 已被其他配置使用");
            return false;
        }
        
        String sql = "UPDATE " + TABLE_NAME + 
            " SET name = ?, description = ?, parameter_string = ?, modified_time = ? WHERE id = ?";
        
        config.updateModifiedTime();
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, config.getName());
            pstmt.setString(2, config.getDescription());
            pstmt.setString(3, config.getParameterString());
            pstmt.setString(4, config.getFormattedModifiedTime());
            pstmt.setLong(5, config.getId());
            
            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                log("[+] 配置已更新: " + config.getName());
                return true;
            }
        } catch (SQLException e) {
            log("[-] 更新配置失败: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * 检查配置名称是否已存在
     */
    public boolean existsByName(String name) {
        String sql = "SELECT COUNT(*) FROM " + TABLE_NAME + " WHERE name = ?";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, name);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            log("[-] 检查配置名称失败: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * 检查配置名称是否已存在（排除指定ID）
     */
    public boolean existsByNameExcludeId(String name, long excludeId) {
        String sql = "SELECT COUNT(*) FROM " + TABLE_NAME + " WHERE name = ? AND id != ?";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, name);
            pstmt.setLong(2, excludeId);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            log("[-] 检查配置名称失败: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * 删除配置
     */
    public boolean delete(long id) {
        String sql = "DELETE FROM " + TABLE_NAME + " WHERE id = ?";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setLong(1, id);
            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                log("[+] 配置已删除, ID: " + id);
                return true;
            }
        } catch (SQLException e) {
            log("[-] 删除配置失败: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * 批量删除配置
     */
    public int deleteByIds(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return 0;
        }
        
        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            placeholders.append(i > 0 ? ",?" : "?");
        }
        
        String sql = "DELETE FROM " + TABLE_NAME + " WHERE id IN (" + placeholders + ")";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            for (int i = 0; i < ids.size(); i++) {
                pstmt.setLong(i + 1, ids.get(i));
            }
            
            int affected = pstmt.executeUpdate();
            log("[+] 批量删除完成, 删除数量: " + affected);
            return affected;
        } catch (SQLException e) {
            log("[-] 批量删除失败: " + e.getMessage());
        }
        return 0;
    }
    
    /**
     * 获取所有配置
     */
    public List<PresetConfig> findAll() {
        String sql = "SELECT * FROM " + TABLE_NAME + " ORDER BY id DESC";
        return executeQuery(sql);
    }
    
    /**
     * 根据ID获取配置
     */
    public PresetConfig findById(long id) {
        String sql = "SELECT * FROM " + TABLE_NAME + " WHERE id = ?";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setLong(1, id);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return mapResultSetToConfig(rs);
            }
        } catch (SQLException e) {
            log("[-] 查询配置失败: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * 搜索配置（支持名称、描述、参数字符串）
     */
    public List<PresetConfig> search(String keyword) {
        String sql = "SELECT * FROM " + TABLE_NAME + 
            " WHERE name LIKE ? OR description LIKE ? OR parameter_string LIKE ? ORDER BY id DESC";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            String pattern = "%" + keyword + "%";
            pstmt.setString(1, pattern);
            pstmt.setString(2, pattern);
            pstmt.setString(3, pattern);
            
            return executeQuery(pstmt);
        } catch (SQLException e) {
            log("[-] 搜索配置失败: " + e.getMessage());
        }
        return new ArrayList<>();
    }
    
    /**
     * 获取配置总数
     */
    public int count() {
        String sql = "SELECT COUNT(*) FROM " + TABLE_NAME;
        
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            log("[-] 统计配置数量失败: " + e.getMessage());
        }
        return 0;
    }
    
    /**
     * 获取配置总数（别名）
     */
    public int getCount() {
        return count();
    }
    
    /**
     * 获取所有配置（别名）
     */
    public List<PresetConfig> getAllConfigs() {
        return findAll();
    }
    
    /**
     * 根据名称获取配置
     */
    public PresetConfig getConfigByName(String name) {
        String sql = "SELECT * FROM " + TABLE_NAME + " WHERE name = ?";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, name);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return mapResultSetToConfig(rs);
            }
        } catch (SQLException e) {
            log("[-] 根据名称查询配置失败: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * 检查名称是否已存在
     */
    public boolean existsByName(String name, Long excludeId) {
        String sql = excludeId != null 
            ? "SELECT COUNT(*) FROM " + TABLE_NAME + " WHERE name = ? AND id != ?"
            : "SELECT COUNT(*) FROM " + TABLE_NAME + " WHERE name = ?";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, name);
            if (excludeId != null) {
                pstmt.setLong(2, excludeId);
            }
            
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            log("[-] 检查名称失败: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * 执行查询并返回结果列表
     */
    private List<PresetConfig> executeQuery(String sql) {
        List<PresetConfig> results = new ArrayList<>();
        
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                results.add(mapResultSetToConfig(rs));
            }
        } catch (SQLException e) {
            log("[-] 查询失败: " + e.getMessage());
        }
        return results;
    }
    
    /**
     * 执行预处理查询并返回结果列表
     */
    private List<PresetConfig> executeQuery(PreparedStatement pstmt) {
        List<PresetConfig> results = new ArrayList<>();
        
        try (ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                results.add(mapResultSetToConfig(rs));
            }
        } catch (SQLException e) {
            log("[-] 查询失败: " + e.getMessage());
        }
        return results;
    }
    
    /**
     * 将ResultSet映射到PresetConfig对象
     */
    private PresetConfig mapResultSetToConfig(ResultSet rs) throws SQLException {
        PresetConfig config = new PresetConfig();
        config.setId(rs.getLong("id"));
        config.setName(rs.getString("name"));
        config.setDescription(rs.getString("description"));
        config.setParameterString(rs.getString("parameter_string"));
        
        String createdTime = rs.getString("created_time");
        String modifiedTime = rs.getString("modified_time");
        
        if (createdTime != null && !createdTime.isEmpty()) {
            config.setCreatedTime(LocalDateTime.parse(createdTime, PresetConfig.DATE_FORMATTER));
        }
        if (modifiedTime != null && !modifiedTime.isEmpty()) {
            config.setModifiedTime(LocalDateTime.parse(modifiedTime, PresetConfig.DATE_FORMATTER));
        }
        
        return config;
    }
    
    /**
     * 记录日志
     */
    private void log(String message) {
        if (logAppender != null) {
            logAppender.accept(message);
        }
    }
    
    /**
     * 获取数据库文件路径
     */
    public String getDbPath() {
        return dbPath;
    }

    // ==================== 命令行执行配置操作 ====================

    /**
     * 获取命令行执行配置
     * 如果配置不存在，创建默认配置
     */
    public CommandExecConfig getCommandExecConfig() {
        String sql = "SELECT * FROM " + COMMAND_EXEC_TABLE + " WHERE id = 1";

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                CommandExecConfig config = new CommandExecConfig();
                config.setAutoCopy(rs.getInt("auto_copy") == 1);
                config.setTempDir(rs.getString("temp_dir"));
                config.setScriptTempDir(rs.getString("script_temp_dir"));
                config.setPythonPath(rs.getString("python_path"));
                config.setSqlmapPath(rs.getString("sqlmap_path"));
                config.setTerminalType(rs.getString("terminal_type"));
                config.setKeepTerminal(rs.getInt("keep_terminal") == 1);
                config.setTitleRules(CommandExecConfig.parseTitleRules(rs.getString("title_rules")));
                config.setTitleFallback(rs.getString("title_fallback"));
                config.setTitleMaxLength(rs.getInt("title_max_length"));
                return config;
            } else {
                // 配置不存在，创建默认配置
                CommandExecConfig defaultConfig = CommandExecConfig.createDefault();
                insertCommandExecConfig(defaultConfig);
                return defaultConfig;
            }
        } catch (SQLException e) {
            log("[-] 获取命令行执行配置失败: " + e.getMessage());
            return CommandExecConfig.createDefault();
        }
    }

    /**
     * 插入默认命令行执行配置
     */
    private void insertCommandExecConfig(CommandExecConfig config) {
        String sql = "INSERT INTO " + COMMAND_EXEC_TABLE + 
            " (id, auto_copy, temp_dir, script_temp_dir, python_path, sqlmap_path, terminal_type, keep_terminal, title_rules, title_fallback, title_max_length) " +
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, config.isAutoCopy() ? 1 : 0);
            pstmt.setString(2, config.getTempDir());
            pstmt.setString(3, config.getScriptTempDir());
            pstmt.setString(4, config.getPythonPath());
            pstmt.setString(5, config.getSqlmapPath());
            pstmt.setString(6, config.getTerminalType());
            pstmt.setInt(7, config.isKeepTerminal() ? 1 : 0);
            pstmt.setString(8, CommandExecConfig.titleRulesToJson(config.getTitleRules()));
            pstmt.setString(9, config.getTitleFallback());
            pstmt.setInt(10, config.getTitleMaxLength());

            pstmt.executeUpdate();
            log("[+] 命令行执行配置初始化成功");
        } catch (SQLException e) {
            log("[-] 插入命令行执行配置失败: " + e.getMessage());
        }
    }

    /**
     * 保存命令行执行配置
     */
    public boolean saveCommandExecConfig(CommandExecConfig config) {
        // 先检查是否存在配置
        boolean exists = checkCommandExecConfigExists();

        if (exists) {
            return updateCommandExecConfig(config);
        } else {
            return insertCommandExecConfigWithResult(config);
        }
    }

    /**
     * 检查命令行执行配置是否存在
     */
    private boolean checkCommandExecConfigExists() {
        String sql = "SELECT COUNT(*) FROM " + COMMAND_EXEC_TABLE + " WHERE id = 1";

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            log("[-] 检查命令行执行配置失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 更新命令行执行配置
     */
    private boolean updateCommandExecConfig(CommandExecConfig config) {
        String sql = "UPDATE " + COMMAND_EXEC_TABLE + 
            " SET auto_copy = ?, temp_dir = ?, script_temp_dir = ?, python_path = ?, sqlmap_path = ?, " +
            "terminal_type = ?, keep_terminal = ?, title_rules = ?, title_fallback = ?, title_max_length = ? " +
            "WHERE id = 1";

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, config.isAutoCopy() ? 1 : 0);
            pstmt.setString(2, config.getTempDir());
            pstmt.setString(3, config.getScriptTempDir());
            pstmt.setString(4, config.getPythonPath());
            pstmt.setString(5, config.getSqlmapPath());
            pstmt.setString(6, config.getTerminalType());
            pstmt.setInt(7, config.isKeepTerminal() ? 1 : 0);
            pstmt.setString(8, CommandExecConfig.titleRulesToJson(config.getTitleRules()));
            pstmt.setString(9, config.getTitleFallback());
            pstmt.setInt(10, config.getTitleMaxLength());

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                log("[+] 命令行执行配置已保存");
                return true;
            }
        } catch (SQLException e) {
            log("[-] 更新命令行执行配置失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 插入命令行执行配置并返回结果
     */
    private boolean insertCommandExecConfigWithResult(CommandExecConfig config) {
        insertCommandExecConfig(config);
        return checkCommandExecConfigExists();
    }
}
