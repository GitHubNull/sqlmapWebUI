package com.sqlmapwebui.burp;

import org.apache.commons.cli.*;

import java.util.*;

/**
 * 扫描参数字符串解析器
 * 使用 Apache Commons CLI 解析命令行格式的扫描参数
 * 
 * 支持的格式：
 * 1. SQLMap 命令行格式: --level=5 --risk=3 --dbms=mysql
 * 2. 空格分隔格式: --level 5 --risk 3 --dbms mysql
 * 3. 短选项: -p id --batch -o
 * 4. 混合格式: --level 5 --risk=3 -p id
 * 
 * @author SQLMap WebUI Team
 * @version 2.0.0
 */
public class ScanConfigParser {
    
    // Apache Commons CLI Options 定义
    private static final Options OPTIONS = new Options();
    
    // 参数元数据映射
    private static final Map<String, ParamMeta> PARAM_META = new LinkedHashMap<>();
    
    // 支持的 DBMS 列表
    private static final Set<String> VALID_DBMS = new HashSet<>(Arrays.asList(
        "mysql", "oracle", "pgsql", "mssql", "sqlite", "access", "firebird",
        "sybase", "sap maxdb", "maxdb", "db2", "hsqldb", "h2", "informix",
        "monetdb", "derby", "vertica", "mckoi", "presto", "altibase",
        "mimersql", "cratedb", "cubrid", "cache", "extremedb", "frontbase",
        "raima", "virtuoso"
    ));
    
    // 支持的 OS 列表
    private static final Set<String> VALID_OS = new HashSet<>(Arrays.asList("linux", "windows"));
    
    // 支持的 technique 字符
    private static final String VALID_TECHNIQUES = "BEUSTQ";
    
    // 支持的 HTTP 方法
    private static final Set<String> VALID_METHODS = new HashSet<>(Arrays.asList(
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"
    ));
    
    static {
        initOptions();
    }
    
    /**
     * 初始化所有命令行选项
     */
    private static void initOptions() {
        // ==================== Detection 检测选项 ====================
        addOption("level", null, "检测级别 (1-5)", Integer.class, 1, 1, 5, null);
        addOption("risk", null, "风险级别 (1-3)", Integer.class, 1, 1, 3, null);
        addOption("string", null, "页面匹配字符串", String.class, "", null, null, null);
        addOption("not-string", "notString", "页面不匹配字符串", String.class, "", null, null, null);
        addOption("regexp", null, "正则匹配", String.class, "", null, null, null);
        addOption("code", null, "HTTP响应码", Integer.class, 0, 100, 599, null);
        addOption("smart", null, "智能检测", Boolean.class, false, null, null, null);
        addOption("text-only", "textOnly", "仅文本比较", Boolean.class, false, null, null, null);
        addOption("titles", null, "基于标题比较", Boolean.class, false, null, null, null);
        
        // ==================== Injection 注入选项 ====================
        addOptionWithShort("p", "test-parameter", "testParameter", "指定测试参数", String.class, "", null, null, null);
        addOption("skip", null, "跳过参数", String.class, "", null, null, null);
        addOption("skip-static", "skipStatic", "跳过静态参数", Boolean.class, false, null, null, null);
        addOption("param-exclude", "paramExclude", "排除参数", String.class, "", null, null, null);
        addOption("dbms", null, "数据库类型", String.class, "", null, null, VALID_DBMS);
        addOption("os", null, "操作系统", String.class, "", null, null, VALID_OS);
        addOption("prefix", null, "注入前缀", String.class, "", null, null, null);
        addOption("suffix", null, "注入后缀", String.class, "", null, null, null);
        addOption("tamper", null, "篡改脚本", String.class, "", null, null, null);
        
        // ==================== Techniques 技术选项 ====================
        addOption("technique", null, "注入技术 (BEUSTQ)", String.class, "", null, null, null);
        addOption("time-sec", "timeSec", "时间盲注延迟(秒)", Integer.class, 5, 1, 60, null);
        
        // ==================== Request 请求选项 ====================
        addOption("method", null, "HTTP方法", String.class, "", null, null, VALID_METHODS);
        addOption("data", null, "POST数据", String.class, "", null, null, null);
        addOption("cookie", null, "Cookie值", String.class, "", null, null, null);
        addOptionWithShort("A", "user-agent", "agent", "User-Agent", String.class, "", null, null, null);
        addOption("referer", null, "Referer", String.class, "", null, null, null);
        addOption("headers", null, "额外请求头", String.class, "", null, null, null);
        addOption("proxy", null, "代理地址", String.class, "", null, null, null);
        addOption("proxy-cred", "proxyCred", "代理认证", String.class, "", null, null, null);
        addOption("delay", null, "请求延迟(秒)", Float.class, 0f, 0f, 60f, null);
        addOption("timeout", null, "超时(秒)", Float.class, 30f, 1f, 300f, null);
        addOption("retries", null, "重试次数", Integer.class, 3, 0, 10, null);
        addOption("random-agent", "randomAgent", "随机UA", Boolean.class, false, null, null, null);
        addOption("tor", null, "使用Tor", Boolean.class, false, null, null, null);
        addOption("force-ssl", "forceSSL", "强制SSL", Boolean.class, false, null, null, null);
        addOption("skip-urlencode", "skipUrlEncode", "跳过URL编码", Boolean.class, false, null, null, null);
        
        // ==================== Optimization 优化选项 ====================
        addOptionWithShort("o", "optimize", null, "优化模式", Boolean.class, false, null, null, null);
        addOption("keep-alive", "keepAlive", "保持连接", Boolean.class, false, null, null, null);
        addOption("null-connection", "nullConnection", "空连接", Boolean.class, false, null, null, null);
        addOption("threads", null, "线程数 (1-10)", Integer.class, 1, 1, 10, null);
        
        // ==================== Enumeration 枚举选项 ====================
        addOption("banner", "getBanner", "获取Banner", Boolean.class, false, null, null, null);
        addOption("current-user", "getCurrentUser", "获取当前用户", Boolean.class, false, null, null, null);
        addOption("current-db", "getCurrentDb", "获取当前数据库", Boolean.class, false, null, null, null);
        addOption("is-dba", "isDba", "是否DBA", Boolean.class, false, null, null, null);
        addOption("users", "getUsers", "获取用户列表", Boolean.class, false, null, null, null);
        addOption("dbs", "getDbs", "获取数据库列表", Boolean.class, false, null, null, null);
        addOption("tables", "getTables", "获取表列表", Boolean.class, false, null, null, null);
        addOption("columns", "getColumns", "获取列列表", Boolean.class, false, null, null, null);
        addOption("dump", "dumpTable", "导出表数据", Boolean.class, false, null, null, null);
        addOption("dump-all", "dumpAll", "导出所有数据", Boolean.class, false, null, null, null);
        addOptionWithShort("D", "db", null, "目标数据库", String.class, "", null, null, null);
        addOptionWithShort("T", "tbl", null, "目标表", String.class, "", null, null, null);
        addOptionWithShort("C", "col", null, "目标列", String.class, "", null, null, null);
        
        // ==================== General 通用选项 ====================
        addOption("batch", null, "非交互模式", Boolean.class, true, null, null, null);
        addOption("forms", null, "解析表单", Boolean.class, false, null, null, null);
        addOption("crawl", "crawlDepth", "爬取深度 (0=禁用)", Integer.class, 0, 0, 10, null);
        addOption("flush-session", "flushSession", "刷新会话", Boolean.class, false, null, null, null);
        addOption("fresh-queries", "freshQueries", "新鲜查询", Boolean.class, false, null, null, null);
        addOptionWithShort("v", "verbose", null, "详细程度 (0-6)", Integer.class, 1, 0, 6, null);
    }
    
    /**
     * 添加长选项
     */
    private static void addOption(String longOpt, String canonicalName, String description,
                                   Class<?> type, Object defaultValue, 
                                   Number minValue, Number maxValue, Set<String> validValues) {
        String name = canonicalName != null ? canonicalName : longOpt.replace("-", "");
        boolean hasArg = type != Boolean.class;
        
        Option option = Option.builder()
            .longOpt(longOpt)
            .hasArg(hasArg)
            .desc(description)
            .build();
        OPTIONS.addOption(option);
        
        ParamMeta meta = new ParamMeta(name, description, type, defaultValue, minValue, maxValue, validValues);
        PARAM_META.put(longOpt, meta);
        if (canonicalName != null && !canonicalName.equals(longOpt)) {
            PARAM_META.put(canonicalName, meta);
        }
    }
    
    /**
     * 添加带短选项的选项
     */
    private static void addOptionWithShort(String shortOpt, String longOpt, String canonicalName,
                                            String description, Class<?> type, Object defaultValue,
                                            Number minValue, Number maxValue, Set<String> validValues) {
        String name = canonicalName != null ? canonicalName : longOpt.replace("-", "");
        boolean hasArg = type != Boolean.class;
        
        Option option = Option.builder(shortOpt)
            .longOpt(longOpt)
            .hasArg(hasArg)
            .desc(description)
            .build();
        OPTIONS.addOption(option);
        
        ParamMeta meta = new ParamMeta(name, description, type, defaultValue, minValue, maxValue, validValues);
        PARAM_META.put(longOpt, meta);
        PARAM_META.put(shortOpt, meta);
        if (canonicalName != null && !canonicalName.equals(longOpt)) {
            PARAM_META.put(canonicalName, meta);
        }
    }
    
    // ==================== 核心解析方法 ====================
    
    /**
     * 解析参数字符串
     * 
     * @param paramString 参数字符串
     * @return 解析结果
     */
    public static ParseResult parse(String paramString) {
        ParseResult result = new ParseResult();
        
        if (paramString == null || paramString.trim().isEmpty()) {
            result.addWarning("参数字符串为空");
            return result;
        }
        
        try {
            // 预处理：规范化字符串
            String normalized = normalizeParamString(paramString);
            
            // 分词为参数数组
            String[] args = tokenize(normalized);
            
            // 使用 Apache Commons CLI 解析
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(OPTIONS, args, true);
            
            // 处理解析后的选项
            processOptions(cmd, result);
            
            // 检查未识别的参数
            List<String> unrecognized = cmd.getArgList();
            for (String arg : unrecognized) {
                if (arg.startsWith("-")) {
                    result.addWarning("未识别的参数: " + arg);
                }
            }
            
        } catch (ParseException e) {
            result.addError("命令行解析错误: " + e.getMessage());
        } catch (Exception e) {
            result.addError("解析异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * 快速解析参数字符串，返回 ScanConfig
     * 如果有错误，抛出异常
     */
    public static ScanConfig parseOrThrow(String paramString) throws IllegalArgumentException {
        ParseResult result = parse(paramString);
        if (result.hasErrors()) {
            throw new IllegalArgumentException("参数解析失败: " + String.join("; ", result.getErrors()));
        }
        return result.getConfig();
    }
    
    /**
     * 尝试解析，忽略错误
     */
    public static ScanConfig parseIgnoreErrors(String paramString) {
        ParseResult result = parse(paramString);
        return result.getConfig();
    }
    
    /**
     * 规范化参数字符串
     */
    private static String normalizeParamString(String input) {
        String result = input.replaceAll("[\\r\\n]+", " ");
        result = result.replaceAll("\\s+", " ");
        return result.trim();
    }
    
    /**
     * 分词为参数数组
     * 支持带引号的字符串
     */
    private static String[] tokenize(String input) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuote = false;
        char quoteChar = 0;
        
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            
            if (inQuote) {
                if (c == quoteChar) {
                    inQuote = false;
                } else {
                    current.append(c);
                }
            } else {
                if (c == '"' || c == '\'') {
                    inQuote = true;
                    quoteChar = c;
                } else if (c == ' ') {
                    if (current.length() > 0) {
                        tokens.add(current.toString());
                        current = new StringBuilder();
                    }
                } else if (c == '=') {
                    if (current.length() > 0) {
                        tokens.add(current.toString());
                        current = new StringBuilder();
                    }
                } else {
                    current.append(c);
                }
            }
        }
        
        if (current.length() > 0) {
            tokens.add(current.toString());
        }
        
        return tokens.toArray(new String[0]);
    }
    
    /**
     * 处理解析后的选项
     */
    private static void processOptions(CommandLine cmd, ParseResult result) {
        for (Option opt : cmd.getOptions()) {
            String optName = opt.getLongOpt() != null ? opt.getLongOpt() : opt.getOpt();
            ParamMeta meta = PARAM_META.get(optName);
            
            if (meta == null) {
                result.addWarning("未知选项: " + optName);
                continue;
            }
            
            String value = opt.getValue();
            result.markParsed(meta.getName(), value);
            
            try {
                if (meta.isBoolean()) {
                    boolean boolValue = true;
                    if (value != null) {
                        boolValue = parseBooleanValue(value);
                    }
                    setConfigValue(result.getConfig(), meta.getName(), boolValue, result);
                    
                } else if (meta.isInteger()) {
                    if (value == null || value.isEmpty()) {
                        result.addError("参数 '" + meta.getName() + "' 需要一个整数值");
                        continue;
                    }
                    int intValue = parseIntegerWithValidation(value, meta, result);
                    setConfigValue(result.getConfig(), meta.getName(), intValue, result);
                    
                } else if (meta.isFloat()) {
                    if (value == null || value.isEmpty()) {
                        result.addError("参数 '" + meta.getName() + "' 需要一个数值");
                        continue;
                    }
                    float floatValue = parseFloatWithValidation(value, meta, result);
                    setConfigValue(result.getConfig(), meta.getName(), floatValue, result);
                    
                } else if (meta.isString()) {
                    if (value == null) {
                        value = "";
                    }
                    String strValue = validateStringValue(value, meta, result);
                    setConfigValue(result.getConfig(), meta.getName(), strValue, result);
                }
                
            } catch (NumberFormatException e) {
                result.addError("参数 '" + meta.getName() + "' 值格式错误: " + e.getMessage());
            } catch (Exception e) {
                result.addError("参数 '" + meta.getName() + "' 处理异常: " + e.getMessage());
            }
        }
    }
    
    /**
     * 解析布尔值
     */
    private static boolean parseBooleanValue(String value) {
        if (value == null) return true;
        String lower = value.toLowerCase().trim();
        return lower.equals("true") || lower.equals("1") || 
               lower.equals("yes") || lower.equals("on") || lower.isEmpty();
    }
    
    /**
     * 解析整数并验证范围
     */
    private static int parseIntegerWithValidation(String value, ParamMeta meta, ParseResult result) {
        int intValue = Integer.parseInt(value.trim());
        
        if (meta.getMinValue() != null && intValue < meta.getMinValue().intValue()) {
            result.addWarning("参数 '" + meta.getName() + "' 值 " + intValue + 
                              " 小于最小值 " + meta.getMinValue() + "，已自动调整");
            intValue = meta.getMinValue().intValue();
        }
        if (meta.getMaxValue() != null && intValue > meta.getMaxValue().intValue()) {
            result.addWarning("参数 '" + meta.getName() + "' 值 " + intValue + 
                              " 大于最大值 " + meta.getMaxValue() + "，已自动调整");
            intValue = meta.getMaxValue().intValue();
        }
        
        return intValue;
    }
    
    /**
     * 解析浮点数并验证范围
     */
    private static float parseFloatWithValidation(String value, ParamMeta meta, ParseResult result) {
        float floatValue = Float.parseFloat(value.trim());
        
        if (meta.getMinValue() != null && floatValue < meta.getMinValue().floatValue()) {
            result.addWarning("参数 '" + meta.getName() + "' 值 " + floatValue + 
                              " 小于最小值 " + meta.getMinValue() + "，已自动调整");
            floatValue = meta.getMinValue().floatValue();
        }
        if (meta.getMaxValue() != null && floatValue > meta.getMaxValue().floatValue()) {
            result.addWarning("参数 '" + meta.getName() + "' 值 " + floatValue + 
                              " 大于最大值 " + meta.getMaxValue() + "，已自动调整");
            floatValue = meta.getMaxValue().floatValue();
        }
        
        return floatValue;
    }
    
    /**
     * 验证字符串值
     */
    private static String validateStringValue(String value, ParamMeta meta, ParseResult result) {
        // 移除首尾引号
        if ((value.startsWith("\"") && value.endsWith("\"")) ||
            (value.startsWith("'") && value.endsWith("'"))) {
            value = value.substring(1, value.length() - 1);
        }
        
        // 对 technique 参数进行特殊验证
        if (meta.getName().equals("technique")) {
            value = validateTechnique(value, result);
        }
        
        // 枚举值验证
        if (meta.hasValidValues() && !value.isEmpty()) {
            String lowerValue = value.toLowerCase();
            boolean found = false;
            String matchedValue = null;
            
            for (String valid : meta.getValidValues()) {
                if (valid.equalsIgnoreCase(lowerValue)) {
                    found = true;
                    matchedValue = valid;
                    break;
                }
            }
            
            if (!found) {
                // 尝试前缀匹配
                for (String valid : meta.getValidValues()) {
                    if (valid.toLowerCase().startsWith(lowerValue)) {
                        result.addWarning("参数 '" + meta.getName() + "' 值 '" + value + 
                                          "' 已匹配为 '" + valid + "'");
                        return valid;
                    }
                }
                
                result.addError("参数 '" + meta.getName() + "' 值 '" + value + 
                                "' 不是有效选项。可选值: " + String.join(", ", meta.getValidValues()));
                return "";
            }
            
            return matchedValue != null ? matchedValue : value;
        }
        
        return value;
    }
    
    /**
     * 验证 technique 参数
     */
    private static String validateTechnique(String value, ParseResult result) {
        StringBuilder validated = new StringBuilder();
        Set<Character> seen = new HashSet<>();
        
        for (char c : value.toUpperCase().toCharArray()) {
            if (VALID_TECHNIQUES.indexOf(c) >= 0) {
                if (!seen.contains(c)) {
                    validated.append(c);
                    seen.add(c);
                } else {
                    result.addWarning("technique 参数中字符 '" + c + "' 重复，已去重");
                }
            } else if (!Character.isWhitespace(c)) {
                result.addWarning("technique 参数中字符 '" + c + "' 无效，已忽略。有效字符: " + VALID_TECHNIQUES);
            }
        }
        
        return validated.toString();
    }
    
    /**
     * 设置配置值
     */
    static void setConfigValue(ScanConfig config, String paramName, 
                                Object value, ParseResult result) {
        try {
            switch (paramName) {
                // Detection
                case "level": config.setLevel((Integer) value); break;
                case "risk": config.setRisk((Integer) value); break;
                case "string": config.setString((String) value); break;
                case "notString": config.setNotString((String) value); break;
                case "regexp": config.setRegexp((String) value); break;
                case "code": config.setCode((Integer) value); break;
                case "smart": config.setSmart((Boolean) value); break;
                case "textOnly": config.setTextOnly((Boolean) value); break;
                case "titles": config.setTitles((Boolean) value); break;
                
                // Injection
                case "testParameter": config.setTestParameter((String) value); break;
                case "skip": config.setSkip((String) value); break;
                case "skipStatic": config.setSkipStatic((Boolean) value); break;
                case "paramExclude": config.setParamExclude((String) value); break;
                case "dbms": config.setDbms((String) value); break;
                case "os": config.setOs((String) value); break;
                case "prefix": config.setPrefix((String) value); break;
                case "suffix": config.setSuffix((String) value); break;
                case "tamper": config.setTamper((String) value); break;
                
                // Techniques
                case "technique": config.setTechnique((String) value); break;
                case "timeSec": config.setTimeSec((Integer) value); break;
                
                // Request
                case "method": config.setMethod(((String) value).toUpperCase()); break;
                case "data": config.setData((String) value); break;
                case "cookie": config.setCookie((String) value); break;
                case "agent": config.setAgent((String) value); break;
                case "referer": config.setReferer((String) value); break;
                case "headers": config.setHeaders((String) value); break;
                case "proxy": config.setProxy((String) value); break;
                case "proxyCred": config.setProxyCred((String) value); break;
                case "delay": config.setDelay((Float) value); break;
                case "timeout": config.setTimeout((Float) value); break;
                case "retries": config.setRetries((Integer) value); break;
                case "randomAgent": config.setRandomAgent((Boolean) value); break;
                case "tor": config.setTor((Boolean) value); break;
                case "forceSSL": config.setForceSSL((Boolean) value); break;
                case "skipUrlEncode": config.setSkipUrlEncode((Boolean) value); break;
                
                // Optimization
                case "optimize": config.setOptimize((Boolean) value); break;
                case "keepAlive": config.setKeepAlive((Boolean) value); break;
                case "nullConnection": config.setNullConnection((Boolean) value); break;
                case "threads": config.setThreads((Integer) value); break;
                
                // Enumeration
                case "getBanner": config.setGetBanner((Boolean) value); break;
                case "getCurrentUser": config.setGetCurrentUser((Boolean) value); break;
                case "getCurrentDb": config.setGetCurrentDb((Boolean) value); break;
                case "isDba": config.setIsDba((Boolean) value); break;
                case "getUsers": config.setGetUsers((Boolean) value); break;
                case "getDbs": config.setGetDbs((Boolean) value); break;
                case "getTables": config.setGetTables((Boolean) value); break;
                case "getColumns": config.setGetColumns((Boolean) value); break;
                case "dumpTable": config.setDumpTable((Boolean) value); break;
                case "dumpAll": config.setDumpAll((Boolean) value); break;
                case "db": config.setDb((String) value); break;
                case "tbl": config.setTbl((String) value); break;
                case "col": config.setCol((String) value); break;
                
                // General
                case "batch": config.setBatch((Boolean) value); break;
                case "forms": config.setForms((Boolean) value); break;
                case "crawlDepth": config.setCrawlDepth((Integer) value); break;
                case "flushSession": config.setFlushSession((Boolean) value); break;
                case "freshQueries": config.setFreshQueries((Boolean) value); break;
                case "verbose": config.setVerbose((Integer) value); break;
                
                default:
                    result.addWarning("未知参数名: " + paramName);
            }
        } catch (ClassCastException e) {
            result.addError("参数 '" + paramName + "' 类型转换失败: " + e.getMessage());
        }
    }
    
    // ==================== 工具方法 ====================
    
    /**
     * 验证参数字符串是否有效
     */
    public static boolean isValid(String paramString) {
        ParseResult result = parse(paramString);
        return !result.hasErrors();
    }
    
    /**
     * 合并两个配置
     */
    public static ScanConfig merge(ScanConfig base, ScanConfig source) {
        ScanConfig merged = base.copy();
        Map<String, Object> sourceOptions = source.toOptionsMap();
        
        for (Map.Entry<String, Object> entry : sourceOptions.entrySet()) {
            try {
                setConfigValue(merged, entry.getKey(), entry.getValue(), new ParseResult());
            } catch (Exception ignored) {
                // 忽略无法设置的参数
            }
        }
        
        return merged;
    }
    
    /**
     * 获取帮助信息
     */
    public static String getHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("========== SQLMap 扫描参数帮助 ==========\n\n");
        sb.append("使用 Apache Commons CLI 解析命令行格式参数\n\n");
        sb.append("支持格式:\n");
        sb.append("  --level=5 --risk=3 --dbms=mysql\n");
        sb.append("  --level 5 --risk 3 --dbms mysql\n");
        sb.append("  -p id --batch -o\n\n");
        
        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(80);
        
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        formatter.printOptions(pw, 80, OPTIONS, 2, 4);
        sb.append(sw.toString());
        
        return sb.toString();
    }
    
    /**
     * 获取 Apache Commons CLI Options 对象
     */
    public static Options getOptions() {
        return OPTIONS;
    }
    
    /**
     * 获取参数元数据映射
     */
    public static Map<String, ParamMeta> getParamMeta() {
        return Collections.unmodifiableMap(PARAM_META);
    }
    
    /**
     * 比较两个参数字符串是否等效
     * 解析后比较实际参数值，而不是字符串形式
     * 
     * @param paramString1 第一个参数字符串
     * @param paramString2 第二个参数字符串
     * @return 是否等效
     */
    public static boolean isEquivalent(String paramString1, String paramString2) {
        // 处理空值情况
        if (paramString1 == null && paramString2 == null) return true;
        if (paramString1 == null || paramString2 == null) return false;
        
        // 字符串完全相同
        String trimmed1 = paramString1.trim();
        String trimmed2 = paramString2.trim();
        if (trimmed1.equals(trimmed2)) return true;
        
        // 都为空
        if (trimmed1.isEmpty() && trimmed2.isEmpty()) return true;
        if (trimmed1.isEmpty() || trimmed2.isEmpty()) return false;
        
        // 解析后比较
        ParseResult result1 = parse(paramString1);
        ParseResult result2 = parse(paramString2);
        
        // 如果解析失败，无法比较
        if (result1.hasErrors() || result2.hasErrors()) {
            return false;
        }
        
        ScanConfig config1 = result1.getConfig();
        ScanConfig config2 = result2.getConfig();
        
        // 比较两个配置的 toOptionsMap
        Map<String, Object> options1 = config1.toOptionsMap();
        Map<String, Object> options2 = config2.toOptionsMap();
        
        return options1.equals(options2);
    }
    
    /**
     * 查找与给定参数字符串等效的配置
     * 
     * @param targetParamString 目标参数字符串
     * @param existingConfigs 现有配置列表
     * @return 等效的配置名称列表
     */
    public static List<String> findEquivalentConfigs(String targetParamString, List<PresetConfig> existingConfigs) {
        List<String> equivalentNames = new ArrayList<>();
        
        if (targetParamString == null || existingConfigs == null || existingConfigs.isEmpty()) {
            return equivalentNames;
        }
        
        for (PresetConfig config : existingConfigs) {
            if (isEquivalent(targetParamString, config.getParameterString())) {
                equivalentNames.add(config.getName());
            }
        }
        
        return equivalentNames;
    }
    
    /**
     * 查找与给定参数字符串等效的配置（排除指定 ID）
     * 
     * @param targetParamString 目标参数字符串
     * @param existingConfigs 现有配置列表
     * @param excludeId 要排除的配置ID
     * @return 等效的配置名称列表
     */
    public static List<String> findEquivalentConfigsExcludeId(String targetParamString, 
                                                               List<PresetConfig> existingConfigs, 
                                                               long excludeId) {
        List<String> equivalentNames = new ArrayList<>();
        
        if (targetParamString == null || existingConfigs == null || existingConfigs.isEmpty()) {
            return equivalentNames;
        }
        
        for (PresetConfig config : existingConfigs) {
            if (config.getId() != excludeId && isEquivalent(targetParamString, config.getParameterString())) {
                equivalentNames.add(config.getName());
            }
        }
        
        return equivalentNames;
    }
}
