package com.sqlmapwebui.burp.panels;

import com.sqlmapwebui.burp.ConfigManager;
import com.sqlmapwebui.burp.SqlmapApiClient;

import javax.swing.*;
import java.util.function.Consumer;

/**
 * 配置面板基类
 * 提供通用功能和依赖注入
 */
public abstract class BaseConfigPanel extends JPanel {
    
    protected final ConfigManager configManager;
    protected final SqlmapApiClient apiClient;
    protected final Consumer<String> logAppender;
    
    protected static final String[] DBMS_OPTIONS = {
        "", "MySQL", "PostgreSQL", "Oracle", "Microsoft SQL Server", 
        "SQLite", "MariaDB", "IBM DB2", "Firebird", "SAP MaxDB"
    };
    
    public BaseConfigPanel(ConfigManager configManager, SqlmapApiClient apiClient, Consumer<String> logAppender) {
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.logAppender = logAppender;
        initializePanel();
    }
    
    /**
     * 初始化面板，子类需要实现
     */
    protected abstract void initializePanel();
    
    /**
     * 追加日志
     */
    protected void appendLog(String message) {
        if (logAppender != null) {
            logAppender.accept(message);
        }
    }
}
