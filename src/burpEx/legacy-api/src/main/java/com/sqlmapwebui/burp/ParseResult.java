package com.sqlmapwebui.burp;

import java.util.*;

/**
 * 扫描参数解析结果
 * 包含解析后的配置、警告信息、错误信息等
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class ParseResult {
    
    /** 解析后的扫描配置 */
    private final ScanConfig config;
    
    /** 警告信息列表 */
    private final List<String> warnings;
    
    /** 错误信息列表 */
    private final List<String> errors;
    
    /** 已解析的参数集合 */
    private final Set<String> parsedParams;
    
    /** 重复的参数集合 */
    private final Set<String> duplicateParams;
    
    /** 原始参数值映射 */
    private final Map<String, String> originalValues;
    
    /**
     * 构造函数
     */
    public ParseResult() {
        this.config = new ScanConfig();
        this.warnings = new ArrayList<>();
        this.errors = new ArrayList<>();
        this.parsedParams = new LinkedHashSet<>();
        this.duplicateParams = new LinkedHashSet<>();
        this.originalValues = new LinkedHashMap<>();
    }
    
    // ==================== Getters ====================
    
    /**
     * 获取解析后的扫描配置
     */
    public ScanConfig getConfig() {
        return config;
    }
    
    /**
     * 获取警告信息列表
     */
    public List<String> getWarnings() {
        return warnings;
    }
    
    /**
     * 获取错误信息列表
     */
    public List<String> getErrors() {
        return errors;
    }
    
    /**
     * 获取已解析的参数集合
     */
    public Set<String> getParsedParams() {
        return parsedParams;
    }
    
    /**
     * 获取重复的参数集合
     */
    public Set<String> getDuplicateParams() {
        return duplicateParams;
    }
    
    /**
     * 获取原始参数值映射
     */
    public Map<String, String> getOriginalValues() {
        return originalValues;
    }
    
    // ==================== 状态判断 ====================
    
    /**
     * 是否有错误
     */
    public boolean hasErrors() {
        return !errors.isEmpty();
    }
    
    /**
     * 是否有警告
     */
    public boolean hasWarnings() {
        return !warnings.isEmpty();
    }
    
    /**
     * 解析是否成功（无错误）
     */
    public boolean isSuccess() {
        return errors.isEmpty();
    }
    
    // ==================== 修改方法 ====================
    
    /**
     * 添加警告信息
     */
    public void addWarning(String warning) {
        warnings.add(warning);
    }
    
    /**
     * 添加错误信息
     */
    public void addError(String error) {
        errors.add(error);
    }
    
    /**
     * 标记参数已解析
     */
    public void markParsed(String param, String value) {
        if (parsedParams.contains(param)) {
            duplicateParams.add(param);
        }
        parsedParams.add(param);
        if (value != null) {
            originalValues.put(param, value);
        }
    }
    
    /**
     * 检查参数是否已解析
     */
    public boolean isParsed(String param) {
        return parsedParams.contains(param);
    }
    
    // ==================== 报告生成 ====================
    
    /**
     * 获取解析摘要
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("解析结果: ").append(isSuccess() ? "成功" : "失败");
        sb.append("\n已解析参数: ").append(parsedParams.size());
        if (!duplicateParams.isEmpty()) {
            sb.append("\n重复参数: ").append(duplicateParams);
        }
        if (!warnings.isEmpty()) {
            sb.append("\n警告: ").append(warnings.size()).append("个");
        }
        if (!errors.isEmpty()) {
            sb.append("\n错误: ").append(errors.size()).append("个");
        }
        return sb.toString();
    }
    
    /**
     * 获取详细的解析报告
     */
    public String getDetailedReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("========== 扫描参数解析报告 ==========\n\n");
        
        // 解析状态
        sb.append("【解析状态】: ").append(isSuccess() ? "✓ 成功" : "✗ 失败").append("\n");
        sb.append("【已解析参数】: ").append(parsedParams.size()).append("个\n");
        
        // 已解析的参数列表
        if (!parsedParams.isEmpty()) {
            sb.append("\n【参数列表】:\n");
            for (String param : parsedParams) {
                sb.append("  • ").append(param);
                if (originalValues.containsKey(param)) {
                    sb.append(" = ").append(originalValues.get(param));
                }
                if (duplicateParams.contains(param)) {
                    sb.append(" (重复)");
                }
                sb.append("\n");
            }
        }
        
        // 重复参数警告
        if (!duplicateParams.isEmpty()) {
            sb.append("\n【重复参数】:\n");
            for (String param : duplicateParams) {
                sb.append("  ⚠ ").append(param).append(" - 使用最后一次出现的值\n");
            }
        }
        
        // 警告信息
        if (!warnings.isEmpty()) {
            sb.append("\n【警告信息】:\n");
            for (String warning : warnings) {
                sb.append("  ⚠ ").append(warning).append("\n");
            }
        }
        
        // 错误信息
        if (!errors.isEmpty()) {
            sb.append("\n【错误信息】:\n");
            for (String error : errors) {
                sb.append("  ✗ ").append(error).append("\n");
            }
        }
        
        sb.append("\n========================================\n");
        return sb.toString();
    }
    
    /**
     * 获取简短的错误描述
     */
    public String getErrorSummary() {
        if (errors.isEmpty()) {
            return "";
        }
        return String.join("; ", errors);
    }
    
    /**
     * 获取简短的警告描述
     */
    public String getWarningSummary() {
        if (warnings.isEmpty()) {
            return "";
        }
        return String.join("; ", warnings);
    }
    
    @Override
    public String toString() {
        return getSummary();
    }
}
