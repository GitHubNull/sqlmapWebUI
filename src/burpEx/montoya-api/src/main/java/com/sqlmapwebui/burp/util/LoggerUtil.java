package com.sqlmapwebui.burp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 日志工具类（Java 17）
 * 统一使用 SLF4J 替代 System.out.println 和 PrintWriter
 */
public final class LoggerUtil {
    
    private LoggerUtil() {
        throw new AssertionError("LoggerUtil cannot be instantiated");
    }
    
    /**
     * 获取 Logger
     */
    public static Logger getLogger(Class<?> clazz) {
        return LoggerFactory.getLogger(clazz);
    }
    
    /**
     * 获取 Logger（使用类名）
     */
    public static Logger getLogger(String name) {
        return LoggerFactory.getLogger(name);
    }
}
