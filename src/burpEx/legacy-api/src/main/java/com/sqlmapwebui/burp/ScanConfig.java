package com.sqlmapwebui.burp;

import com.google.gson.Gson;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 扫描配置模型
 * 存储SQLMap扫描参数配置
 * 
 * 参数名称与 sqlmap 的 optiondict.py 完全一致，确保前后端对接正确
 */
public class ScanConfig {
    
    private String name;
    private String description;
    
    // ==================== Detection 检测选项 ====================
    private int level = 1;              // --level (1-5) 检测级别
    private int risk = 1;               // --risk (1-3) 风险级别
    private String string = "";         // --string 页面匹配字符串
    private String notString = "";      // --not-string 页面不匹配字符串
    private String regexp = "";         // --regexp 正则匹配
    private int code = 0;               // --code HTTP响应码
    private boolean smart = false;      // --smart 智能检测
    private boolean textOnly = false;   // --text-only 仅文本比较
    private boolean titles = false;     // --titles 基于标题比较
    
    // ==================== Injection 注入选项 ====================
    private String testParameter = "";  // -p/--test-parameter 指定测试参数
    private String skip = "";           // --skip 跳过参数
    private boolean skipStatic = false; // --skip-static 跳过静态参数
    private String paramExclude = "";   // --param-exclude 排除参数
    private String dbms = "";           // --dbms 数据库类型
    private String os = "";             // --os 操作系统
    private String prefix = "";         // --prefix 注入前缀
    private String suffix = "";         // --suffix 注入后缀
    private String tamper = "";         // --tamper 篡改脚本
    
    // ==================== Techniques 技术选项 ====================
    private String technique = "";      // --technique (BEUSTQ)
    private int timeSec = 5;            // --time-sec 时间盲注延迟
    
    // ==================== Request 请求选项 ====================
    private String method = "";         // --method HTTP方法
    private String data = "";           // --data POST数据
    private String cookie = "";         // --cookie Cookie值
    private String agent = "";          // --user-agent/--agent
    private String referer = "";        // --referer
    private String headers = "";        // --headers 额外请求头
    private String proxy = "";          // --proxy 代理
    private String proxyCred = "";      // --proxy-cred 代理认证
    private float delay = 0;            // --delay 请求延迟(秒)
    private float timeout = 30;         // --timeout 超时(秒)
    private int retries = 3;            // --retries 重试次数
    private boolean randomAgent = false;// --random-agent 随机UA
    private boolean tor = false;        // --tor 使用Tor
    private boolean forceSSL = false;   // --force-ssl 强制SSL
    private boolean skipUrlEncode = false; // --skip-urlencode
    
    // ==================== Optimization 优化选项 ====================
    private boolean optimize = false;   // -o/--optimize
    private boolean keepAlive = false;  // --keep-alive
    private boolean nullConnection = false; // --null-connection
    private int threads = 1;            // --threads 线程数(1-10)
    
    // ==================== Enumeration 枚举选项 ====================
    private boolean getBanner = false;  // --banner
    private boolean getCurrentUser = false; // --current-user
    private boolean getCurrentDb = false;   // --current-db
    private boolean isDba = false;      // --is-dba
    private boolean getUsers = false;   // --users
    private boolean getDbs = false;     // --dbs
    private boolean getTables = false;  // --tables
    private boolean getColumns = false; // --columns
    private boolean dumpTable = false;  // --dump
    private boolean dumpAll = false;    // --dump-all
    private String db = "";             // -D database
    private String tbl = "";            // -T table
    private String col = "";            // -C columns
    
    // ==================== General 通用选项 ====================
    private boolean batch = true;       // --batch 非交互模式
    private boolean forms = false;      // --forms 解析表单
    private int crawlDepth = 0;         // --crawl 爬取深度(0=禁用)
    private boolean flushSession = false; // --flush-session
    private boolean freshQueries = false; // --fresh-queries
    private int verbose = 1;            // -v/--verbose (0-6)
    
    // ==================== 额外参数（支持任意SQLMap参数）====================
    private String extraArgs = "";      // 存储所有未被识别的参数，原样传递给后端
    private Map<String, Object> extraOptions = new HashMap<>();  // 存储解析后的额外参数，传递给后端
    
    // ==================== 元数据 ====================
    private long createdAt;
    private long lastUsedAt;
    
    public ScanConfig() {
        this.createdAt = System.currentTimeMillis();
        this.lastUsedAt = this.createdAt;
    }
    
    public ScanConfig(String name) {
        this();
        this.name = name;
    }
    
    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    // Detection
    public int getLevel() { return level; }
    public void setLevel(int level) { this.level = Math.max(1, Math.min(5, level)); }
    
    public int getRisk() { return risk; }
    public void setRisk(int risk) { this.risk = Math.max(1, Math.min(3, risk)); }
    
    public String getString() { return string; }
    public void setString(String string) { this.string = string; }
    
    public String getNotString() { return notString; }
    public void setNotString(String notString) { this.notString = notString; }
    
    public String getRegexp() { return regexp; }
    public void setRegexp(String regexp) { this.regexp = regexp; }
    
    public int getCode() { return code; }
    public void setCode(int code) { this.code = code; }
    
    public boolean isSmart() { return smart; }
    public void setSmart(boolean smart) { this.smart = smart; }
    
    public boolean isTextOnly() { return textOnly; }
    public void setTextOnly(boolean textOnly) { this.textOnly = textOnly; }
    
    public boolean isTitles() { return titles; }
    public void setTitles(boolean titles) { this.titles = titles; }
    
    // Injection
    public String getTestParameter() { return testParameter; }
    public void setTestParameter(String testParameter) { this.testParameter = testParameter; }
    
    public String getSkip() { return skip; }
    public void setSkip(String skip) { this.skip = skip; }
    
    public boolean isSkipStatic() { return skipStatic; }
    public void setSkipStatic(boolean skipStatic) { this.skipStatic = skipStatic; }
    
    public String getParamExclude() { return paramExclude; }
    public void setParamExclude(String paramExclude) { this.paramExclude = paramExclude; }
    
    public String getDbms() { return dbms; }
    public void setDbms(String dbms) { this.dbms = dbms; }
    
    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }
    
    public String getPrefix() { return prefix; }
    public void setPrefix(String prefix) { this.prefix = prefix; }
    
    public String getSuffix() { return suffix; }
    public void setSuffix(String suffix) { this.suffix = suffix; }
    
    public String getTamper() { return tamper; }
    public void setTamper(String tamper) { this.tamper = tamper; }
    
    // Techniques
    public String getTechnique() { return technique; }
    public void setTechnique(String technique) { this.technique = technique; }
    
    public int getTimeSec() { return timeSec; }
    public void setTimeSec(int timeSec) { this.timeSec = Math.max(1, timeSec); }
    
    // Request
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
    
    public String getCookie() { return cookie; }
    public void setCookie(String cookie) { this.cookie = cookie; }
    
    public String getAgent() { return agent; }
    public void setAgent(String agent) { this.agent = agent; }
    
    public String getReferer() { return referer; }
    public void setReferer(String referer) { this.referer = referer; }
    
    public String getHeaders() { return headers; }
    public void setHeaders(String headers) { this.headers = headers; }
    
    public String getProxy() { return proxy; }
    public void setProxy(String proxy) { this.proxy = proxy; }
    
    public String getProxyCred() { return proxyCred; }
    public void setProxyCred(String proxyCred) { this.proxyCred = proxyCred; }
    
    public float getDelay() { return delay; }
    public void setDelay(float delay) { this.delay = Math.max(0, delay); }
    
    public float getTimeout() { return timeout; }
    public void setTimeout(float timeout) { this.timeout = Math.max(1, timeout); }
    
    public int getRetries() { return retries; }
    public void setRetries(int retries) { this.retries = Math.max(0, retries); }
    
    public boolean isRandomAgent() { return randomAgent; }
    public void setRandomAgent(boolean randomAgent) { this.randomAgent = randomAgent; }
    
    public boolean isTor() { return tor; }
    public void setTor(boolean tor) { this.tor = tor; }
    
    public boolean isForceSSL() { return forceSSL; }
    public void setForceSSL(boolean forceSSL) { this.forceSSL = forceSSL; }
    
    public boolean isSkipUrlEncode() { return skipUrlEncode; }
    public void setSkipUrlEncode(boolean skipUrlEncode) { this.skipUrlEncode = skipUrlEncode; }
    
    // Optimization
    public boolean isOptimize() { return optimize; }
    public void setOptimize(boolean optimize) { this.optimize = optimize; }
    
    public boolean isKeepAlive() { return keepAlive; }
    public void setKeepAlive(boolean keepAlive) { this.keepAlive = keepAlive; }
    
    public boolean isNullConnection() { return nullConnection; }
    public void setNullConnection(boolean nullConnection) { this.nullConnection = nullConnection; }
    
    public int getThreads() { return threads; }
    public void setThreads(int threads) { this.threads = Math.max(1, Math.min(10, threads)); }
    
    // Enumeration
    public boolean isGetBanner() { return getBanner; }
    public void setGetBanner(boolean getBanner) { this.getBanner = getBanner; }
    
    public boolean isGetCurrentUser() { return getCurrentUser; }
    public void setGetCurrentUser(boolean getCurrentUser) { this.getCurrentUser = getCurrentUser; }
    
    public boolean isGetCurrentDb() { return getCurrentDb; }
    public void setGetCurrentDb(boolean getCurrentDb) { this.getCurrentDb = getCurrentDb; }
    
    public boolean isIsDba() { return isDba; }
    public void setIsDba(boolean isDba) { this.isDba = isDba; }
    
    public boolean isGetUsers() { return getUsers; }
    public void setGetUsers(boolean getUsers) { this.getUsers = getUsers; }
    
    public boolean isGetDbs() { return getDbs; }
    public void setGetDbs(boolean getDbs) { this.getDbs = getDbs; }
    
    public boolean isGetTables() { return getTables; }
    public void setGetTables(boolean getTables) { this.getTables = getTables; }
    
    public boolean isGetColumns() { return getColumns; }
    public void setGetColumns(boolean getColumns) { this.getColumns = getColumns; }
    
    public boolean isDumpTable() { return dumpTable; }
    public void setDumpTable(boolean dumpTable) { this.dumpTable = dumpTable; }
    
    public boolean isDumpAll() { return dumpAll; }
    public void setDumpAll(boolean dumpAll) { this.dumpAll = dumpAll; }
    
    public String getDb() { return db; }
    public void setDb(String db) { this.db = db; }
    
    public String getTbl() { return tbl; }
    public void setTbl(String tbl) { this.tbl = tbl; }
    
    public String getCol() { return col; }
    public void setCol(String col) { this.col = col; }
    
    // General
    public boolean isBatch() { return batch; }
    public void setBatch(boolean batch) { this.batch = batch; }
    
    public boolean isForms() { return forms; }
    public void setForms(boolean forms) { this.forms = forms; }
    
    public int getCrawlDepth() { return crawlDepth; }
    public void setCrawlDepth(int crawlDepth) { this.crawlDepth = Math.max(0, Math.min(10, crawlDepth)); }
    
    public boolean isFlushSession() { return flushSession; }
    public void setFlushSession(boolean flushSession) { this.flushSession = flushSession; }
    
    public boolean isFreshQueries() { return freshQueries; }
    public void setFreshQueries(boolean freshQueries) { this.freshQueries = freshQueries; }
    
    public int getVerbose() { return verbose; }
    public void setVerbose(int verbose) { this.verbose = Math.max(0, Math.min(6, verbose)); }
    
    // Extra Args
    public String getExtraArgs() { return extraArgs; }
    public void setExtraArgs(String extraArgs) { this.extraArgs = extraArgs != null ? extraArgs : ""; }
    
    // Extra Options
    public Map<String, Object> getExtraOptions() { return extraOptions; }
    public void setExtraOptions(Map<String, Object> extraOptions) { 
        this.extraOptions = extraOptions != null ? extraOptions : new HashMap<>(); 
    }
    public void addExtraOption(String key, Object value) {
        if (key != null && !key.isEmpty()) {
            this.extraOptions.put(key, value);
        }
    }
    
    // Metadata
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    
    public long getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(long lastUsedAt) { this.lastUsedAt = lastUsedAt; }
    
    public void updateLastUsed() {
        this.lastUsedAt = System.currentTimeMillis();
    }
    
    /**
     * 转换为提交给后端的options Map
     * 参数名称与 sqlmap optiondict.py 完全一致
     */
    public Map<String, Object> toOptionsMap() {
        Map<String, Object> options = new HashMap<>();
        
        // Detection
        if (level != 1) options.put("level", level);
        if (risk != 1) options.put("risk", risk);
        if (!string.isEmpty()) options.put("string", string);
        if (!notString.isEmpty()) options.put("notString", notString);
        if (!regexp.isEmpty()) options.put("regexp", regexp);
        if (code > 0) options.put("code", code);
        if (smart) options.put("smart", true);
        if (textOnly) options.put("textOnly", true);
        if (titles) options.put("titles", true);
        
        // Injection
        if (!testParameter.isEmpty()) options.put("testParameter", testParameter);
        if (!skip.isEmpty()) options.put("skip", skip);
        if (skipStatic) options.put("skipStatic", true);
        if (!paramExclude.isEmpty()) options.put("paramExclude", paramExclude);
        if (!dbms.isEmpty()) options.put("dbms", dbms);
        if (!os.isEmpty()) options.put("os", os);
        if (!prefix.isEmpty()) options.put("prefix", prefix);
        if (!suffix.isEmpty()) options.put("suffix", suffix);
        if (!tamper.isEmpty()) options.put("tamper", tamper);
        
        // Techniques
        if (!technique.isEmpty()) options.put("technique", technique);
        if (timeSec != 5) options.put("timeSec", timeSec);
        
        // Request
        if (!method.isEmpty()) options.put("method", method);
        if (!data.isEmpty()) options.put("data", data);
        if (!cookie.isEmpty()) options.put("cookie", cookie);
        if (!agent.isEmpty()) options.put("agent", agent);
        if (!referer.isEmpty()) options.put("referer", referer);
        if (!headers.isEmpty()) options.put("headers", headers);
        if (!proxy.isEmpty()) options.put("proxy", proxy);
        if (!proxyCred.isEmpty()) options.put("proxyCred", proxyCred);
        if (delay > 0) options.put("delay", delay);
        if (timeout != 30) options.put("timeout", timeout);
        if (retries != 3) options.put("retries", retries);
        if (randomAgent) options.put("randomAgent", true);
        if (tor) options.put("tor", true);
        if (forceSSL) options.put("forceSSL", true);
        if (skipUrlEncode) options.put("skipUrlEncode", true);
        
        // Optimization
        if (optimize) options.put("optimize", true);
        if (keepAlive) options.put("keepAlive", true);
        if (nullConnection) options.put("nullConnection", true);
        if (threads > 1) options.put("threads", threads);
        
        // Enumeration
        if (getBanner) options.put("getBanner", true);
        if (getCurrentUser) options.put("getCurrentUser", true);
        if (getCurrentDb) options.put("getCurrentDb", true);
        if (isDba) options.put("isDba", true);
        if (getUsers) options.put("getUsers", true);
        if (getDbs) options.put("getDbs", true);
        if (getTables) options.put("getTables", true);
        if (getColumns) options.put("getColumns", true);
        if (dumpTable) options.put("dumpTable", true);
        if (dumpAll) options.put("dumpAll", true);
        if (!db.isEmpty()) options.put("db", db);
        if (!tbl.isEmpty()) options.put("tbl", tbl);
        if (!col.isEmpty()) options.put("col", col);
        
        // General
        options.put("batch", batch);
        if (forms) options.put("forms", true);
        if (crawlDepth > 0) options.put("crawlDepth", crawlDepth);
        if (flushSession) options.put("flushSession", true);
        if (freshQueries) options.put("freshQueries", true);
        if (verbose != 1) options.put("verbose", verbose);
        
        // Extra Options - 支持任意额外的SQLMap参数
        if (extraOptions != null && !extraOptions.isEmpty()) {
            options.putAll(extraOptions);
        }
        
        return options;
    }
    
    /**
     * 克隆配置
     */
    public ScanConfig copy() {
        ScanConfig copy = new ScanConfig();
        copy.name = this.name;
        copy.description = this.description;
        
        // Detection
        copy.level = this.level;
        copy.risk = this.risk;
        copy.string = this.string;
        copy.notString = this.notString;
        copy.regexp = this.regexp;
        copy.code = this.code;
        copy.smart = this.smart;
        copy.textOnly = this.textOnly;
        copy.titles = this.titles;
        
        // Injection
        copy.testParameter = this.testParameter;
        copy.skip = this.skip;
        copy.skipStatic = this.skipStatic;
        copy.paramExclude = this.paramExclude;
        copy.dbms = this.dbms;
        copy.os = this.os;
        copy.prefix = this.prefix;
        copy.suffix = this.suffix;
        copy.tamper = this.tamper;
        
        // Techniques
        copy.technique = this.technique;
        copy.timeSec = this.timeSec;
        
        // Request
        copy.method = this.method;
        copy.data = this.data;
        copy.cookie = this.cookie;
        copy.agent = this.agent;
        copy.referer = this.referer;
        copy.headers = this.headers;
        copy.proxy = this.proxy;
        copy.proxyCred = this.proxyCred;
        copy.delay = this.delay;
        copy.timeout = this.timeout;
        copy.retries = this.retries;
        copy.randomAgent = this.randomAgent;
        copy.tor = this.tor;
        copy.forceSSL = this.forceSSL;
        copy.skipUrlEncode = this.skipUrlEncode;
        
        // Optimization
        copy.optimize = this.optimize;
        copy.keepAlive = this.keepAlive;
        copy.nullConnection = this.nullConnection;
        copy.threads = this.threads;
        
        // Enumeration
        copy.getBanner = this.getBanner;
        copy.getCurrentUser = this.getCurrentUser;
        copy.getCurrentDb = this.getCurrentDb;
        copy.isDba = this.isDba;
        copy.getUsers = this.getUsers;
        copy.getDbs = this.getDbs;
        copy.getTables = this.getTables;
        copy.getColumns = this.getColumns;
        copy.dumpTable = this.dumpTable;
        copy.dumpAll = this.dumpAll;
        copy.db = this.db;
        copy.tbl = this.tbl;
        copy.col = this.col;
        
        // General
        copy.batch = this.batch;
        copy.forms = this.forms;
        copy.crawlDepth = this.crawlDepth;
        copy.flushSession = this.flushSession;
        copy.freshQueries = this.freshQueries;
        copy.verbose = this.verbose;
        
        // Extra
        copy.extraArgs = this.extraArgs;
        copy.extraOptions = new HashMap<>(this.extraOptions);
        
        // Metadata
        copy.createdAt = System.currentTimeMillis();
        copy.lastUsedAt = copy.createdAt;
        return copy;
    }
    
    /**
     * 生成命令行参数字符串
     * 用于在历史记录中显示
     */
    public String toCommandLineString() {
        StringBuilder sb = new StringBuilder();
        
        // Detection
        if (level != 1) sb.append("--level=").append(level).append(" ");
        if (risk != 1) sb.append("--risk=").append(risk).append(" ");
        if (!string.isEmpty()) sb.append("--string=").append(string).append(" ");
        if (!notString.isEmpty()) sb.append("--not-string=").append(notString).append(" ");
        if (!regexp.isEmpty()) sb.append("--regexp=").append(regexp).append(" ");
        if (code > 0) sb.append("--code=").append(code).append(" ");
        if (smart) sb.append("--smart ");
        if (textOnly) sb.append("--text-only ");
        if (titles) sb.append("--titles ");
        
        // Injection
        if (!testParameter.isEmpty()) sb.append("-p=").append(testParameter).append(" ");
        if (!skip.isEmpty()) sb.append("--skip=").append(skip).append(" ");
        if (skipStatic) sb.append("--skip-static ");
        if (!paramExclude.isEmpty()) sb.append("--param-exclude=").append(paramExclude).append(" ");
        if (!dbms.isEmpty()) sb.append("--dbms=").append(dbms).append(" ");
        if (!os.isEmpty()) sb.append("--os=").append(os).append(" ");
        if (!prefix.isEmpty()) sb.append("--prefix=").append(prefix).append(" ");
        if (!suffix.isEmpty()) sb.append("--suffix=").append(suffix).append(" ");
        if (!tamper.isEmpty()) sb.append("--tamper=").append(tamper).append(" ");
        
        // Techniques
        if (!technique.isEmpty()) sb.append("--technique=").append(technique).append(" ");
        if (timeSec != 5) sb.append("--time-sec=").append(timeSec).append(" ");
        
        // Request
        if (!method.isEmpty()) sb.append("--method=").append(method).append(" ");
        if (!proxy.isEmpty()) sb.append("--proxy=").append(proxy).append(" ");
        if (delay > 0) sb.append("--delay=").append(delay).append(" ");
        if (timeout != 30) sb.append("--timeout=").append(timeout).append(" ");
        if (retries != 3) sb.append("--retries=").append(retries).append(" ");
        if (randomAgent) sb.append("--random-agent ");
        if (tor) sb.append("--tor ");
        if (forceSSL) sb.append("--force-ssl ");
        if (skipUrlEncode) sb.append("--skip-urlencode ");
        
        // Optimization
        if (optimize) sb.append("-o ");
        if (keepAlive) sb.append("--keep-alive ");
        if (nullConnection) sb.append("--null-connection ");
        if (threads > 1) sb.append("--threads=").append(threads).append(" ");
        
        // Enumeration
        if (getBanner) sb.append("--banner ");
        if (getCurrentUser) sb.append("--current-user ");
        if (getCurrentDb) sb.append("--current-db ");
        if (isDba) sb.append("--is-dba ");
        if (getUsers) sb.append("--users ");
        if (getDbs) sb.append("--dbs ");
        if (getTables) sb.append("--tables ");
        if (getColumns) sb.append("--columns ");
        if (dumpTable) sb.append("--dump ");
        if (dumpAll) sb.append("--dump-all ");
        if (!db.isEmpty()) sb.append("-D=").append(db).append(" ");
        if (!tbl.isEmpty()) sb.append("-T=").append(tbl).append(" ");
        if (!col.isEmpty()) sb.append("-C=").append(col).append(" ");
        
        // General
        if (batch) sb.append("--batch ");
        if (forms) sb.append("--forms ");
        if (crawlDepth > 0) sb.append("--crawl=").append(crawlDepth).append(" ");
        if (flushSession) sb.append("--flush-session ");
        if (freshQueries) sb.append("--fresh-queries ");
        if (verbose != 1) sb.append("-v=").append(verbose).append(" ");
        
        return sb.toString().trim();
    }
    
    /**
     * 序列化为JSON
     */
    public String toJson() {
        return new Gson().toJson(this);
    }
    
    /**
     * 从JSON反序列化
     */
    public static ScanConfig fromJson(String json) {
        return new Gson().fromJson(json, ScanConfig.class);
    }
    
    @Override
    public String toString() {
        return name != null ? name : "Unnamed Config";
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScanConfig that = (ScanConfig) o;
        return Objects.equals(name, that.name);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
    
    /**
     * 创建默认配置
     */
    public static ScanConfig createDefault() {
        ScanConfig config = new ScanConfig("Default");
        config.setDescription("默认扫描配置");
        config.setLevel(1);
        config.setRisk(1);
        config.setBatch(true);
        return config;
    }
    
    /**
     * 创建深度扫描配置
     */
    public static ScanConfig createDeepScan() {
        ScanConfig config = new ScanConfig("Deep Scan");
        config.setDescription("深度扫描 - 更高的level和risk");
        config.setLevel(5);
        config.setRisk(3);
        config.setBatch(true);
        return config;
    }
    
    /**
     * 创建快速扫描配置
     */
    public static ScanConfig createQuickScan() {
        ScanConfig config = new ScanConfig("Quick Scan");
        config.setDescription("快速扫描 - 仅基础检测");
        config.setLevel(1);
        config.setRisk(1);
        config.setTechnique("B");
        config.setBatch(true);
        return config;
    }
    
    // ==================== 参数字符串解析方法 ====================
    
    /**
     * 从命令行参数字符串创建 ScanConfig
     * 支持多种格式：
     * - SQLMap 命令行格式: --level=5 --risk=3 --dbms=mysql
     * - 简化格式: level=5 risk=3 dbms=mysql
     * - 短选项: -p id --batch -o
     * - 混合格式: --level 5 --risk 3 -p id
     * 
     * @param paramString 参数字符串
     * @return 解析结果对象，包含 ScanConfig、警告和错误信息
     */
    public static ParseResult parseFromString(String paramString) {
        return ScanConfigParser.parse(paramString);
    }
    
    /**
     * 从命令行参数字符串创建 ScanConfig（快捷方法）
     * 如果解析有错误则抛出异常
     * 
     * @param paramString 参数字符串
     * @return ScanConfig 对象
     * @throws IllegalArgumentException 如果参数解析失败
     */
    public static ScanConfig fromCommandLineString(String paramString) throws IllegalArgumentException {
        return ScanConfigParser.parseOrThrow(paramString);
    }
    
    /**
     * 从命令行参数字符串创建 ScanConfig（忽略错误）
     * 即使有解析错误也会返回配置，无法解析的参数使用默认值
     * 
     * @param paramString 参数字符串
     * @return ScanConfig 对象（可能包含默认值）
     */
    public static ScanConfig fromCommandLineStringSafe(String paramString) {
        return ScanConfigParser.parseIgnoreErrors(paramString);
    }
    
    /**
     * 验证参数字符串是否有效
     * 
     * @param paramString 参数字符串
     * @return true 如果参数字符串可以成功解析（没有错误）
     */
    public static boolean isValidParamString(String paramString) {
        return ScanConfigParser.isValid(paramString);
    }
    
    /**
     * 从参数字符串合并配置
     * 将参数字符串解析后的值合并到当前配置中
     * 
     * @param paramString 参数字符串
     * @return 合并后的新配置对象
     */
    public ScanConfig mergeFromString(String paramString) {
        ScanConfig parsed = ScanConfigParser.parseIgnoreErrors(paramString);
        return ScanConfigParser.merge(this, parsed);
    }
}
