package com.sqlmapwebui.burp;

import java.util.Set;

/**
 * 扫描参数元数据
 * 描述单个参数的类型、约束和校验规则
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class ParamMeta {
    
    /** 规范名称 (camelCase，与 ScanConfig 字段对应) */
    private final String name;
    
    /** 参数描述 */
    private final String description;
    
    /** 参数类型 (Integer.class, Float.class, String.class, Boolean.class) */
    private final Class<?> type;
    
    /** 默认值 */
    private final Object defaultValue;
    
    /** 最小值 (仅数字类型) */
    private final Number minValue;
    
    /** 最大值 (仅数字类型) */
    private final Number maxValue;
    
    /** 有效值集合 (枚举类型) */
    private final Set<String> validValues;
    
    /** 是否被 SQLMap RESTAPI 限制 */
    private final boolean restApiRestricted;
    
    /** 限制原因描述 */
    private final String restrictionReason;
    
    /** 是否为危险参数 */
    private final boolean dangerous;
    
    /** 危险级别描述 */
    private final String dangerLevel;
    
    /**
     * 构造函数（带 RESTAPI 限制和安全标记）
     */
    public ParamMeta(String name, String description, Class<?> type,
                    Object defaultValue, Number minValue, Number maxValue,
                    Set<String> validValues,
                    boolean restApiRestricted, String restrictionReason,
                    boolean dangerous, String dangerLevel) {
        this.name = name;
        this.description = description;
        this.type = type;
        this.defaultValue = defaultValue;
        this.minValue = minValue;
        this.maxValue = maxValue;
        this.validValues = validValues;
        this.restApiRestricted = restApiRestricted;
        this.restrictionReason = restrictionReason;
        this.dangerous = dangerous;
        this.dangerLevel = dangerLevel;
    }
    
    /**
     * 构造函数（简化版本，用于向后兼容）
     */
    public ParamMeta(String name, String description, Class<?> type,
                    Object defaultValue, Number minValue, Number maxValue,
                    Set<String> validValues) {
        this(name, description, type, defaultValue, minValue, maxValue, validValues,
           false, null, false, null);
    }
    
    // ==================== Getters ====================
    
    public String getName() {
        return name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public Class<?> getType() {
        return type;
    }
    
    public Object getDefaultValue() {
        return defaultValue;
    }
    
    public Number getMinValue() {
        return minValue;
    }
    
    public Number getMaxValue() {
        return maxValue;
    }
    
    public Set<String> getValidValues() {
        return validValues;
    }
    
    // ==================== 便捷方法 ====================
    
    /**
     * 是否为布尔类型
     */
    public boolean isBoolean() {
        return type == Boolean.class;
    }
    
    /**
     * 是否为整数类型
     */
    public boolean isInteger() {
        return type == Integer.class;
    }
    
    /**
     * 是否为浮点数类型
     */
    public boolean isFloat() {
        return type == Float.class;
    }
    
    /**
     * 是否为字符串类型
     */
    public boolean isString() {
        return type == String.class;
    }
    
    /**
     * 是否有值范围约束
     */
    public boolean hasRange() {
        return minValue != null || maxValue != null;
    }
    
    /**
     * 是否有枚举约束
     */
    public boolean hasValidValues() {
        return validValues != null && !validValues.isEmpty();
    }
    
    /**
     * 是否需要参数值
     */
    public boolean requiresValue() {
        return !isBoolean();
    }
    
    /**
     * 是否被 SQLMap RESTAPI 限制
     */
    public boolean isRestApiRestricted() {
        return restApiRestricted;
    }
    
    /**
     * 获取限制原因描述
     */
    public String getRestrictionReason() {
        return restrictionReason;
    }
    
    /**
     * 是否为危险参数
     */
    public boolean isDangerous() {
        return dangerous;
    }
    
    /**
     * 获取危险级别描述
     */
    public String getDangerLevel() {
        return dangerLevel;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append(" (").append(type.getSimpleName()).append(")");
        if (hasRange()) {
            sb.append(" [");
            if (minValue != null) sb.append(minValue);
            sb.append("-");
            if (maxValue != null) sb.append(maxValue);
            sb.append("]");
        }
        if (hasValidValues()) {
            sb.append(" {").append(String.join(",", validValues)).append("}");
        }
        return sb.toString();
    }
    
    /**
     * 获取完整描述（包含安全提示）
     */
    public String getFullDescription() {
        StringBuilder desc = new StringBuilder(description);
        if (restApiRestricted && restrictionReason != null) {
            desc.append(" | 🚫 ").append(restrictionReason);
        }
        if (dangerous && dangerLevel != null) {
            desc.append(" | ⚠️ ").append(dangerLevel);
        }
        return desc.toString();
    }
}
