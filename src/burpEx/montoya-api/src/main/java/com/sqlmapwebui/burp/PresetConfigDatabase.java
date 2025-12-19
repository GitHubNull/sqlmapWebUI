package com.sqlmapwebui.burp;

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
    
    private final String dbPath;
    private final Consumer<String> logAppender;
    
    public PresetConfigDatabase(Consumer<String> logAppender) {
        this.logAppender = logAppender;
        // 获取Burp Suite运行目录
        String userDir = System.getProperty("user.dir");
        this.dbPath = new File(userDir, DB_FILE_NAME).getAbsolutePath();
        
        initializeDatabase();
    }
    
    /**
     * 初始化数据库
     */
    private void initializeDatabase() {
        String createTableSQL = 
            "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "name TEXT NOT NULL, " +
            "description TEXT, " +
            "parameter_string TEXT NOT NULL, " +
            "created_time TEXT NOT NULL, " +
            "modified_time TEXT NOT NULL" +
            ")";
        
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSQL);
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
        String sql = "INSERT INTO " + TABLE_NAME + 
            " (name, description, parameter_string, created_time, modified_time) VALUES (?, ?, ?, ?, ?)";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            
            pstmt.setString(1, config.getName());
            pstmt.setString(2, config.getDescription());
            pstmt.setString(3, config.getParameterString());
            pstmt.setString(4, config.getFormattedCreatedTime());
            pstmt.setString(5, config.getFormattedModifiedTime());
            
            int affected = pstmt.executeUpdate();
            
            if (affected > 0) {
                ResultSet rs = pstmt.getGeneratedKeys();
                if (rs.next()) {
                    config.setId(rs.getLong(1));
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
}
