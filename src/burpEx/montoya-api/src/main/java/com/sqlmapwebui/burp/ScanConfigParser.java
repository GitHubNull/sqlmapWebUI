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
    
    // SQLMap 所有合法参数名称集合（排除 -r，从 sqlmap --help 提取）
    private static final Set<String> ALL_SQLMAP_PARAMS = new HashSet<>(Arrays.asList(
        // Target (exclude -r)
        "u", "url", "d", "direct", "l", "logFile", "m", "bulkFile", "g", "googleDork", "c", "configFile",
        // Request
        "A", "user-agent", "H", "header", "method", "data", "param-del", "cookie", "cookie-del",
        "live-cookies", "load-cookies", "drop-set-cookie", "mobile", "random-agent", "host", "referer",
        "headers", "auth-type", "auth-cred", "auth-file", "abort-code", "ignore-code", "ignore-proxy",
        "ignore-redirects", "ignore-timeouts", "proxy", "proxy-cred", "proxy-file", "proxy-freq",
        "tor", "tor-port", "tor-type", "check-tor", "delay", "timeout", "retries", "retry-on",
        "randomize", "safe-url", "safe-post", "safe-req", "safe-freq", "skip-urlencode",
        "csrf-token", "csrf-url", "csrf-method", "csrf-data", "csrf-retries",
        "force-ssl", "chunked", "hpp", "eval", "http10", "http2",
        // Optimization
        "o", "predict-output", "keep-alive", "null-connection", "threads",
        // Injection
        "p", "skip", "skip-static", "param-exclude", "param-filter", "dbms", "dbms-cred", "os",
        "invalid-bignum", "invalid-logical", "invalid-string", "no-cast", "no-escape",
        "prefix", "suffix", "tamper",
        // Detection
        "level", "risk", "string", "not-string", "regexp", "code", "smart", "text-only", "titles",
        // Techniques
        "technique", "time-sec", "disable-stats", "union-cols", "union-char", "union-from",
        "union-values", "dns-domain", "second-url", "second-req",
        // Fingerprint
        "f", "fingerprint",
        // Enumeration
        "a", "all", "b", "banner", "current-user", "current-db", "hostname", "is-dba",
        "users", "passwords", "privileges", "roles", "dbs", "tables", "columns", "schema",
        "count", "dump", "dump-all", "search", "comments", "statements",
        "D", "T", "C", "X", "U", "exclude-sysdbs", "pivot-column", "where",
        "start", "stop", "first", "last", "sql-query", "sql-shell", "sql-file",
        // Brute force
        "common-tables", "common-columns", "common-files",
        // UDF
        "udf-inject", "shared-lib",
        // File system
        "file-read", "file-write", "file-dest",
        // OS access
        "os-cmd", "os-shell", "os-pwn", "os-smbrelay", "os-bof", "priv-esc", "msf-path", "tmp-path",
        // Windows registry
        "reg-read", "reg-add", "reg-del", "reg-key", "reg-value", "reg-data", "reg-type",
        // General
        "s", "t", "abort-on-empty", "answers", "base64", "base64-safe", "batch",
        "binary-fields", "check-internet", "cleanup", "crawl", "crawl-exclude",
        "csv-del", "charset", "dump-file", "dump-format", "encoding", "eta",
        "flush-session", "forms", "fresh-queries", "gpage", "har", "hex",
        "output-dir", "parse-errors", "preprocess", "postprocess", "repair",
        "save", "scope", "skip-heuristics", "skip-waf", "table-prefix",
        "test-filter", "test-skip", "time-limit", "unsafe-naming", "web-root",
        // Miscellaneous
        "z", "alert", "beep", "dependencies", "disable-coloring", "disable-hashing",
        "list-tampers", "no-logging", "no-truncate", "offline", "purge",
        "results-file", "shell", "tmp-dir", "unstable", "update", "wizard",
        // Verbose
        "v", "verbose", "hh", "version"
    ));
    
    // 参数名规范化映射（短选项/带连字符 -> 后端参数名）
    private static final Map<String, String> PARAM_NAME_MAP = new HashMap<>();
    
    static {
        initOptions();
        initParamNameMap();
    }
    
    /**
     * 初始化参数名映射
     */
    private static void initParamNameMap() {
        // 短选项映射
        PARAM_NAME_MAP.put("u", "url");
        PARAM_NAME_MAP.put("A", "agent");
        PARAM_NAME_MAP.put("H", "header");
        PARAM_NAME_MAP.put("p", "testParameter");
        PARAM_NAME_MAP.put("o", "optimize");
        PARAM_NAME_MAP.put("f", "extensiveFp");
        PARAM_NAME_MAP.put("a", "getAll");
        PARAM_NAME_MAP.put("b", "getBanner");
        PARAM_NAME_MAP.put("D", "db");
        PARAM_NAME_MAP.put("T", "tbl");
        PARAM_NAME_MAP.put("C", "col");
        PARAM_NAME_MAP.put("X", "exclude");
        PARAM_NAME_MAP.put("U", "user");
        PARAM_NAME_MAP.put("s", "sessionFile");
        PARAM_NAME_MAP.put("t", "trafficFile");
        PARAM_NAME_MAP.put("z", "mnemonics");
        PARAM_NAME_MAP.put("v", "verbose");
        
        // 带连字符的参数名 -> 驼峰命名
        PARAM_NAME_MAP.put("user-agent", "agent");
        PARAM_NAME_MAP.put("not-string", "notString");
        PARAM_NAME_MAP.put("text-only", "textOnly");
        PARAM_NAME_MAP.put("skip-static", "skipStatic");
        PARAM_NAME_MAP.put("param-exclude", "paramExclude");
        PARAM_NAME_MAP.put("param-filter", "paramFilter");
        PARAM_NAME_MAP.put("param-del", "paramDel");
        PARAM_NAME_MAP.put("cookie-del", "cookieDel");
        PARAM_NAME_MAP.put("live-cookies", "liveCookies");
        PARAM_NAME_MAP.put("load-cookies", "loadCookies");
        PARAM_NAME_MAP.put("drop-set-cookie", "dropSetCookie");
        PARAM_NAME_MAP.put("random-agent", "randomAgent");
        PARAM_NAME_MAP.put("auth-type", "authType");
        PARAM_NAME_MAP.put("auth-cred", "authCred");
        PARAM_NAME_MAP.put("auth-file", "authFile");
        PARAM_NAME_MAP.put("abort-code", "abortCode");
        PARAM_NAME_MAP.put("ignore-code", "ignoreCode");
        PARAM_NAME_MAP.put("ignore-proxy", "ignoreProxy");
        PARAM_NAME_MAP.put("ignore-redirects", "ignoreRedirects");
        PARAM_NAME_MAP.put("ignore-timeouts", "ignoreTimeouts");
        PARAM_NAME_MAP.put("proxy-cred", "proxyCred");
        PARAM_NAME_MAP.put("proxy-file", "proxyFile");
        PARAM_NAME_MAP.put("proxy-freq", "proxyFreq");
        PARAM_NAME_MAP.put("tor-port", "torPort");
        PARAM_NAME_MAP.put("tor-type", "torType");
        PARAM_NAME_MAP.put("check-tor", "checkTor");
        PARAM_NAME_MAP.put("retry-on", "retryOn");
        PARAM_NAME_MAP.put("safe-url", "safeUrl");
        PARAM_NAME_MAP.put("safe-post", "safePost");
        PARAM_NAME_MAP.put("safe-req", "safeReqFile");
        PARAM_NAME_MAP.put("safe-freq", "safeFreq");
        PARAM_NAME_MAP.put("skip-urlencode", "skipUrlEncode");
        PARAM_NAME_MAP.put("csrf-token", "csrfToken");
        PARAM_NAME_MAP.put("csrf-url", "csrfUrl");
        PARAM_NAME_MAP.put("csrf-method", "csrfMethod");
        PARAM_NAME_MAP.put("csrf-data", "csrfData");
        PARAM_NAME_MAP.put("csrf-retries", "csrfRetries");
        PARAM_NAME_MAP.put("force-ssl", "forceSSL");
        PARAM_NAME_MAP.put("predict-output", "predictOutput");
        PARAM_NAME_MAP.put("keep-alive", "keepAlive");
        PARAM_NAME_MAP.put("null-connection", "nullConnection");
        PARAM_NAME_MAP.put("dbms-cred", "dbmsCred");
        PARAM_NAME_MAP.put("invalid-bignum", "invalidBignum");
        PARAM_NAME_MAP.put("invalid-logical", "invalidLogical");
        PARAM_NAME_MAP.put("invalid-string", "invalidString");
        PARAM_NAME_MAP.put("no-cast", "noCast");
        PARAM_NAME_MAP.put("no-escape", "noEscape");
        PARAM_NAME_MAP.put("time-sec", "timeSec");
        PARAM_NAME_MAP.put("disable-stats", "disableStats");
        PARAM_NAME_MAP.put("union-cols", "uCols");
        PARAM_NAME_MAP.put("union-char", "uChar");
        PARAM_NAME_MAP.put("union-from", "uFrom");
        PARAM_NAME_MAP.put("union-values", "uValues");
        PARAM_NAME_MAP.put("dns-domain", "dnsDomain");
        PARAM_NAME_MAP.put("second-url", "secondUrl");
        PARAM_NAME_MAP.put("second-req", "secondReq");
        PARAM_NAME_MAP.put("current-user", "getCurrentUser");
        PARAM_NAME_MAP.put("current-db", "getCurrentDb");
        PARAM_NAME_MAP.put("is-dba", "isDba");
        PARAM_NAME_MAP.put("dump-all", "dumpAll");
        PARAM_NAME_MAP.put("exclude-sysdbs", "excludeSysDbs");
        PARAM_NAME_MAP.put("pivot-column", "pivotColumn");
        PARAM_NAME_MAP.put("sql-query", "sqlQuery");
        PARAM_NAME_MAP.put("sql-shell", "sqlShell");
        PARAM_NAME_MAP.put("sql-file", "sqlFile");
        PARAM_NAME_MAP.put("common-tables", "commonTables");
        PARAM_NAME_MAP.put("common-columns", "commonColumns");
        PARAM_NAME_MAP.put("common-files", "commonFiles");
        PARAM_NAME_MAP.put("udf-inject", "udfInject");
        PARAM_NAME_MAP.put("shared-lib", "shLib");
        PARAM_NAME_MAP.put("file-read", "fileRead");
        PARAM_NAME_MAP.put("file-write", "fileWrite");
        PARAM_NAME_MAP.put("file-dest", "fileDest");
        PARAM_NAME_MAP.put("os-cmd", "osCmd");
        PARAM_NAME_MAP.put("os-shell", "osShell");
        PARAM_NAME_MAP.put("os-pwn", "osPwn");
        PARAM_NAME_MAP.put("os-smbrelay", "osSmb");
        PARAM_NAME_MAP.put("os-bof", "osBof");
        PARAM_NAME_MAP.put("priv-esc", "privEsc");
        PARAM_NAME_MAP.put("msf-path", "msfPath");
        PARAM_NAME_MAP.put("tmp-path", "tmpPath");
        PARAM_NAME_MAP.put("reg-read", "regRead");
        PARAM_NAME_MAP.put("reg-add", "regAdd");
        PARAM_NAME_MAP.put("reg-del", "regDel");
        PARAM_NAME_MAP.put("reg-key", "regKey");
        PARAM_NAME_MAP.put("reg-value", "regVal");
        PARAM_NAME_MAP.put("reg-data", "regData");
        PARAM_NAME_MAP.put("reg-type", "regType");
        PARAM_NAME_MAP.put("abort-on-empty", "abortOnEmpty");
        PARAM_NAME_MAP.put("base64-safe", "base64Safe");
        PARAM_NAME_MAP.put("binary-fields", "binaryFields");
        PARAM_NAME_MAP.put("check-internet", "checkInternet");
        PARAM_NAME_MAP.put("crawl-exclude", "crawlExclude");
        PARAM_NAME_MAP.put("csv-del", "csvDel");
        PARAM_NAME_MAP.put("dump-file", "dumpFile");
        PARAM_NAME_MAP.put("dump-format", "dumpFormat");
        PARAM_NAME_MAP.put("flush-session", "flushSession");
        PARAM_NAME_MAP.put("fresh-queries", "freshQueries");
        PARAM_NAME_MAP.put("output-dir", "outputDir");
        PARAM_NAME_MAP.put("parse-errors", "parseErrors");
        PARAM_NAME_MAP.put("skip-heuristics", "skipHeuristics");
        PARAM_NAME_MAP.put("skip-waf", "skipWaf");
        PARAM_NAME_MAP.put("table-prefix", "tablePrefix");
        PARAM_NAME_MAP.put("test-filter", "testFilter");
        PARAM_NAME_MAP.put("test-skip", "testSkip");
        PARAM_NAME_MAP.put("time-limit", "timeLimit");
        PARAM_NAME_MAP.put("unsafe-naming", "unsafeNaming");
        PARAM_NAME_MAP.put("web-root", "webRoot");
        PARAM_NAME_MAP.put("disable-coloring", "disableColoring");
        PARAM_NAME_MAP.put("disable-hashing", "disableHashing");
        PARAM_NAME_MAP.put("list-tampers", "listTampers");
        PARAM_NAME_MAP.put("no-logging", "noLogging");
        PARAM_NAME_MAP.put("no-truncate", "noTruncate");
        PARAM_NAME_MAP.put("results-file", "resultsFile");
        PARAM_NAME_MAP.put("tmp-dir", "tmpDir");
        PARAM_NAME_MAP.put("http1.0", "http10");
        
        // 一些简单的转换
        PARAM_NAME_MAP.put("banner", "getBanner");
        PARAM_NAME_MAP.put("dump", "dumpTable");
        PARAM_NAME_MAP.put("crawl", "crawlDepth");
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
            
            // 使用 Apache Commons CLI 解析已知参数
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(OPTIONS, args, true);
            
            // 处理解析后的已知选项
            processOptions(cmd, result);
            
            // 处理未识别的参数 - 检查是否是合法的SQLMap参数
            List<String> unrecognized = cmd.getArgList();
            processUnrecognizedArgs(unrecognized, result);
            
        } catch (ParseException e) {
            result.addError("命令行解析错误: " + e.getMessage());
        } catch (Exception e) {
            result.addError("解析异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * 处理未被 Apache Commons CLI 识别的参数
     * 如果是合法的SQLMap参数，存入extraOptions
     */
    private static void processUnrecognizedArgs(List<String> args, ParseResult result) {
        for (int i = 0; i < args.size(); i++) {
            String arg = args.get(i);
            
            if (!arg.startsWith("-")) {
                continue; // 跳过非参数的值
            }
            
            // 提取参数名
            String paramName = arg.startsWith("--") ? arg.substring(2) : arg.substring(1);
            
            // 跳过 -r 参数
            if (paramName.equals("r") || paramName.equals("requestFile")) {
                result.addWarning("参数 '-r' 不支持，已忽略");
                continue;
            }
            
            // 检查是否是合法的SQLMap参数
            if (ALL_SQLMAP_PARAMS.contains(paramName)) {
                // 获取规范化的参数名
                String canonicalName = PARAM_NAME_MAP.getOrDefault(paramName, paramName);
                
                // 尝试获取参数值（下一个不以-开头的元素）
                Object value = true; // 默认为布尔真
                if (i + 1 < args.size() && !args.get(i + 1).startsWith("-")) {
                    String nextArg = args.get(i + 1);
                    // 尝试解析为数字
                    value = parseValue(nextArg);
                    i++; // 跳过已处理的值
                }
                
                // 存入extraOptions
                result.getConfig().addExtraOption(canonicalName, value);
            } else {
                // 不是合法的SQLMap参数，忽略并跳过
                // 不输出警告，静默忽略非法参数
            }
        }
    }
    
    /**
     * 解析参数值，尝试转换为适当的类型
     */
    private static Object parseValue(String value) {
        if (value == null || value.isEmpty()) {
            return true;
        }
        
        // 尝试解析为布尔
        String lower = value.toLowerCase();
        if (lower.equals("true") || lower.equals("false")) {
            return Boolean.parseBoolean(lower);
        }
        
        // 尝试解析为整数
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {}
        
        // 尝试解析为浮点数
        try {
            return Float.parseFloat(value);
        } catch (NumberFormatException ignored) {}
        
        // 默认为字符串
        return value;
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
