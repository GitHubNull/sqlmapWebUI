package com.sqlmapwebui.burp;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 常用配置数据模型
 * 用于存储SQLMap扫描参数配置
 */
public class PresetConfig {
    
    public static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    private long id;
    private String name;
    private String description;
    private String parameterString;  // 扫描参数字符串
    private LocalDateTime createdTime;
    private LocalDateTime modifiedTime;
    
    public PresetConfig() {
        this.createdTime = LocalDateTime.now();
        this.modifiedTime = LocalDateTime.now();
    }
    
    public PresetConfig(String name, String description, String parameterString) {
        this.name = name;
        this.description = description;
        this.parameterString = parameterString;
        this.createdTime = LocalDateTime.now();
        this.modifiedTime = LocalDateTime.now();
    }
    
    // Getters and Setters
    
    public long getId() {
        return id;
    }
    
    public void setId(long id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public String getParameterString() {
        return parameterString;
    }
    
    public void setParameterString(String parameterString) {
        this.parameterString = parameterString;
    }
    
    public LocalDateTime getCreatedTime() {
        return createdTime;
    }
    
    public void setCreatedTime(LocalDateTime createdTime) {
        this.createdTime = createdTime;
    }
    
    public LocalDateTime getModifiedTime() {
        return modifiedTime;
    }
    
    public void setModifiedTime(LocalDateTime modifiedTime) {
        this.modifiedTime = modifiedTime;
    }
    
    /**
     * 更新修改时间为当前时间
     */
    public void updateModifiedTime() {
        this.modifiedTime = LocalDateTime.now();
    }
    
    /**
     * 获取格式化的创建时间
     */
    public String getFormattedCreatedTime() {
        return createdTime != null ? createdTime.format(DATE_FORMATTER) : "";
    }
    
    /**
     * 获取格式化的修改时间
     */
    public String getFormattedModifiedTime() {
        return modifiedTime != null ? modifiedTime.format(DATE_FORMATTER) : "";
    }
    
    @Override
    public String toString() {
        return name + " - " + parameterString;
    }
}
