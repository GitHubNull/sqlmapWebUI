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
    
    // ==================== Target 目标选项（高优先级）====================
    private String direct = "";          // -d 直接数据库连接
    private String logFile = "";         // -l 日志文件
    private String bulkFile = "";        // -m 批量文件
    private String sessionFile = "";     // -s 会话文件
    private String googleDork = "";      // -g Google dork
    private String configFile = "";       // -c 配置文件
    
    // ==================== General 扩展选项（高优先级）====================
    private String trafficFile = "";     // -t 流量文件
    private boolean abortOnEmpty = false; // --abort-on-empty 空结果中止
    private String answers = "";         // --answers 预定义答案
    private String base64Parameter = ""; // --base64 Base64参数
    private boolean base64Safe = false; // --base64-safe 安全Base64
    private String binaryFields = "";    // --binary-fields 二进制字段
    private String charset = "";         // --charset 字符集
    private boolean checkInternet = false; // --check-internet 检查网络
    private boolean cleanup = false;     // --cleanup 清理
    private String crawlExclude = "";    // --crawl-exclude 排除爬取
    private String csvDel = "";         // --csv-del CSV分隔符
    private String dumpFile = "";        // --dump-file 导出文件
    private String dumpFormat = "";      // --dump-format 导出格式
    private String encoding = "";        // --encoding 编码
    private int googlePage = 0;         // --gpage Google页码
    private String harFile = "";         // --har HAR文件
    private boolean hexConvert = false;   // --hex 十六进制
    private String outputDir = "";       // --output-dir 输出目录
    private boolean parseErrors = false; // --parse-errors 解析错误
    private String preprocess = "";      // --preprocess 预处理脚本
    private String postprocess = "";     // --postprocess 后处理脚本
    private boolean repair = false;      // --repair 修复
    private String saveConfig = "";      // --save 保存配置
    private String scope = "";           // --scope 目标范围
    private boolean skipHeuristics = false; // --skip-heuristics 跳过启发式
    private boolean skipWaf = false;    // --skip-waf 跳过WAF检测
    private String tablePrefix = "";     // --table-prefix 表前缀
    private String testFilter = "";      // --test-filter 测试过滤
    private String testSkip = "";        // --test-skip 跳过测试
    private float timeLimit = 0;         // --time-limit 时间限制
    private boolean unsafeNaming = false; // --unsafe-naming 不安全命名
    private String webRoot = "";         // --web-root Web根目录
    
    // ==================== Request 扩展选项（高优先级）====================
    private String paramDel = "";         // --param-del 参数分隔符
    private String cookieDel = "";       // --cookie-del cookie分隔符
    private String liveCookies = "";      // --live-cookies 实时cookies
    private String loadCookies = "";      // --load-cookies 加载cookie文件
    private boolean dropSetCookie = false; // --drop-set-cookie 忽略Set-Cookie
    private boolean http2 = false;        // --http2 使用HTTP/2
    private boolean http10 = false;       // --http1.0 使用HTTP/1.0
    private boolean mobile = false;       // --mobile 模拟移动端
    private String authType = "";        // --auth-type HTTP认证类型
    private String authCred = "";        // --auth-cred HTTP认证凭据
    private String authFile = "";         // --auth-file HTTP认证文件
    private String abortCode = "";        // --abort-code 中止错误码
    private String ignoreCode = "";       // --ignore-code 忽略错误码
    private boolean ignoreProxy = false;  // --ignore-proxy 忽略系统代理
    private boolean ignoreRedirects = false; // --ignore-redirects 忽略重定向
    private boolean ignoreTimeouts = false; // --ignore-timeouts 忽略超时
    private String proxyFile = "";       // --proxy-file 代理文件
    private int proxyFreq = 0;           // --proxy-freq 代理切换频率
    private int torPort = 9050;         // --tor-port Tor端口
    private String torType = "SOCKS5";   // --tor-type Tor类型
    private boolean checkTor = false;    // --check-tor 检查Tor
    private String retryOn = "";         // --retry-on 重试匹配
    private String rParam = "";           // --randomize 随机化参数
    private String safeUrl = "";          // --safe-url 安全URL
    private String safePost = "";        // --safe-post 安全POST
    private String safeReqFile = "";      // --safe-req 安全请求文件
    private int safeFreq = 0;            // --safe-freq 安全访问频率
    private String csrfToken = "";        // --csrf-token CSRF令牌参数
    private String csrfUrl = "";          // --csrf-url CSRF获取URL
    private String csrfMethod = "";       // --csrf-method CSRF方法
    private String csrfData = "";         // --csrf-data CSRF数据
    private int csrfRetries = 0;        // --csrf-retries CSRF重试次数
    private boolean chunked = false;      // --chunked 分块传输
    private boolean hpp = false;         // --hpp HTTP参数污染
    private String evalCode = "";         // --eval Python代码执行
    
    // ==================== Optimization 扩展选项====================
    private boolean predictOutput = false; // --predict-output 预测输出
    
    // ==================== Injection 扩展选项====================
    private String paramFilter = "";      // --param-filter 参数过滤
    private String dbmsCred = "";        // --dbms-cred 数据库凭据
    private boolean invalidBignum = false; // --invalid-bignum 大数无效化
    private boolean invalidLogical = false; // --invalid-logical 逻辑无效化
    private boolean invalidString = false; // --invalid-string 字符串无效化
    private boolean noCast = false;       // --no-cast 禁用类型转换
    private boolean noEscape = false;     // --no-escape 禁用转义
    
    // ==================== Techniques 扩展选项====================
    private boolean disableStats = false; // --disable-stats 禁用统计模型
    private String uCols = "";           // --union-cols UNION列数
    private String uChar = "";           // --union-char UNION字符
    private String uFrom = "";           // --union-from UNION表
    private String uValues = "";         // --union-values UNION值
    private String dnsDomain = "";       // --dns-domain DNS外泄域名
    private String secondUrl = "";       // --second-url 二阶URL
    private String secondReq = "";       // --second-req 二阶请求
    
    // ==================== Fingerprint 扩展选项====================
    private boolean extensiveFp = false; // -f/--fingerprint 扩展指纹
    
    // ==================== Enumeration 扩展选项====================
    private boolean getAll = false;       // -a/--all 获取所有
    private boolean getHostname = false;  // --hostname 获取主机名
    private boolean getPasswords = false; // --passwords 获取密码哈希
    private boolean getPrivileges = false; // --privileges 获取权限
    private boolean getRoles = false;     // --roles 获取角色
    private boolean getSchema = false;    // --schema 获取架构
    private boolean getCount = false;      // --count 获取条目数
    private boolean search = false;       // --search 搜索
    private boolean getComments = false;  // --comments 获取注释
    private boolean getStatements = false; // --statements 获取SQL语句
    private String exclude = "";          // -X 排除数据库
    private String pivotColumn = "";      // --pivot-column 轴心列
    private String dumpWhere = "";       // --where 导出WHERE条件
    private String user = "";            // -U 用户
    private boolean excludeSysDbs = false; // --exclude-sysdbs 排除系统库
    private int limitStart = 0;          // --start 起始行
    private int limitStop = 0;           // --stop 结束行
    private int firstChar = 0;           // --first 起始字符
    private int lastChar = 0;            // --last 结束字符
    private String sqlQuery = "";         // --sql-query SQL查询
    private boolean sqlShell = false;     // --sql-shell SQL shell (RESTAPI会阻止)
    private String sqlFile = "";          // --sql-file SQL文件
    
    // ==================== Brute force 暴力破解====================
    private boolean commonTables = false;  // --common-tables 常见表
    private boolean commonColumns = false; // --common-columns 常见列
    private boolean commonFiles = false;  // --common-files 常见文件
    
    // ==================== User-defined function UDF注入====================
    private boolean udfInject = false;    // --udf-inject 注入UDF
    private String shLib = "";           // --shared-lib 共享库
    
    // ==================== File system 文件系统====================
    private String fileRead = "";        // --file-read 读取文件
    private String fileWrite = "";       // --file-write 写入文件
    private String fileDest = "";        // --file-dest 目标文件路径
    
    // ==================== OS takeover 操作系统接管====================
    private String osCmd = "";           // --os-cmd 执行OS命令
    private boolean osPwn = false;       // --os-pwn OOB shell
    private boolean osSmb = false;       // --os-smbrelay SMB中继
    private boolean osBof = false;       // --os-bof 缓冲区溢出
    private boolean privEsc = false;     // --priv-esc 权限提升
    private String msfPath = "";         // --msf-path Metasploit路径
    private String tmpPath = "";         // --tmp-path 临时路径
    
    // ==================== Windows registry Windows注册表====================
    private boolean regRead = false;     // --reg-read 读取注册表
    private boolean regAdd = false;      // --reg-add 添加注册表
    private boolean regDel = false;      // --reg-del 删除注册表
    private String regKey = "";          // --reg-key 注册表键
    private String regVal = "";          // --reg-value 注册表值
    private String regData = "";         // --reg-data 注册表数据
    private String regType = "";         // --reg-type 注册表类型
    
    // ==================== Miscellaneous 其他选项====================
    private String alert = "";           // --alert 警告命令
    private boolean beep = false;        // --beep 蜂鸣
    private boolean dependencies = false; // --dependencies 检查依赖
    private boolean disableColoring = false; // --disable-coloring 禁用颜色
    private boolean disableHashing = false; // --disable-hashing 禁用哈希
    private boolean listTampers = false; // --list-tampers 列出tamper脚本
    private boolean noLogging = false;  // --no-logging 禁用日志
    private boolean noTruncate = false;  // --no-truncate 禁用截断
    private boolean offline = false;     // --offline 离线模式
    private boolean purge = false;       // --purge 清理数据
    private String resultsFile = "";     // --results-file 结果文件
    private String tmpDir = "";         // --tmp-dir 临时目录
    private boolean unstable = false;    // --unstable 不稳定连接调整
    private String mnemonics = "";       // -z 助记符
    
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
    
    // ==================== Target Getters and Setters ====================
    public String getDirect() { return direct; }
    public void setDirect(String direct) { this.direct = direct; }
    
    public String getLogFile() { return logFile; }
    public void setLogFile(String logFile) { this.logFile = logFile; }
    
    public String getBulkFile() { return bulkFile; }
    public void setBulkFile(String bulkFile) { this.bulkFile = bulkFile; }
    
    public String getSessionFile() { return sessionFile; }
    public void setSessionFile(String sessionFile) { this.sessionFile = sessionFile; }
    
    public String getGoogleDork() { return googleDork; }
    public void setGoogleDork(String googleDork) { this.googleDork = googleDork; }
    
    public String getConfigFile() { return configFile; }
    public void setConfigFile(String configFile) { this.configFile = configFile; }
    
    // ==================== General Extended Getters and Setters ====================
    public String getTrafficFile() { return trafficFile; }
    public void setTrafficFile(String trafficFile) { this.trafficFile = trafficFile; }
    
    public boolean isAbortOnEmpty() { return abortOnEmpty; }
    public void setAbortOnEmpty(boolean abortOnEmpty) { this.abortOnEmpty = abortOnEmpty; }
    
    public String getAnswers() { return answers; }
    public void setAnswers(String answers) { this.answers = answers; }
    
    public String getBase64Parameter() { return base64Parameter; }
    public void setBase64Parameter(String base64Parameter) { this.base64Parameter = base64Parameter; }
    
    public boolean isBase64Safe() { return base64Safe; }
    public void setBase64Safe(boolean base64Safe) { this.base64Safe = base64Safe; }
    
    public String getBinaryFields() { return binaryFields; }
    public void setBinaryFields(String binaryFields) { this.binaryFields = binaryFields; }
    
    public String getCharset() { return charset; }
    public void setCharset(String charset) { this.charset = charset; }
    
    public boolean isCheckInternet() { return checkInternet; }
    public void setCheckInternet(boolean checkInternet) { this.checkInternet = checkInternet; }
    
    public boolean isCleanup() { return cleanup; }
    public void setCleanup(boolean cleanup) { this.cleanup = cleanup; }
    
    public String getCrawlExclude() { return crawlExclude; }
    public void setCrawlExclude(String crawlExclude) { this.crawlExclude = crawlExclude; }
    
    public String getCsvDel() { return csvDel; }
    public void setCsvDel(String csvDel) { this.csvDel = csvDel; }
    
    public String getDumpFile() { return dumpFile; }
    public void setDumpFile(String dumpFile) { this.dumpFile = dumpFile; }
    
    public String getDumpFormat() { return dumpFormat; }
    public void setDumpFormat(String dumpFormat) { this.dumpFormat = dumpFormat; }
    
    public String getEncoding() { return encoding; }
    public void setEncoding(String encoding) { this.encoding = encoding; }
    
    public int getGooglePage() { return googlePage; }
    public void setGooglePage(int googlePage) { this.googlePage = Math.max(0, googlePage); }
    
    public String getHarFile() { return harFile; }
    public void setHarFile(String harFile) { this.harFile = harFile; }
    
    public boolean isHexConvert() { return hexConvert; }
    public void setHexConvert(boolean hexConvert) { this.hexConvert = hexConvert; }
    
    public String getOutputDir() { return outputDir; }
    public void setOutputDir(String outputDir) { this.outputDir = outputDir; }
    
    public boolean isParseErrors() { return parseErrors; }
    public void setParseErrors(boolean parseErrors) { this.parseErrors = parseErrors; }
    
    public String getPreprocess() { return preprocess; }
    public void setPreprocess(String preprocess) { this.preprocess = preprocess; }
    
    public String getPostprocess() { return postprocess; }
    public void setPostprocess(String postprocess) { this.postprocess = postprocess; }
    
    public boolean isRepair() { return repair; }
    public void setRepair(boolean repair) { this.repair = repair; }
    
    public String getSaveConfig() { return saveConfig; }
    public void setSaveConfig(String saveConfig) { this.saveConfig = saveConfig; }
    
    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
    
    public boolean isSkipHeuristics() { return skipHeuristics; }
    public void setSkipHeuristics(boolean skipHeuristics) { this.skipHeuristics = skipHeuristics; }
    
    public boolean isSkipWaf() { return skipWaf; }
    public void setSkipWaf(boolean skipWaf) { this.skipWaf = skipWaf; }
    
    public String getTablePrefix() { return tablePrefix; }
    public void setTablePrefix(String tablePrefix) { this.tablePrefix = tablePrefix; }
    
    public String getTestFilter() { return testFilter; }
    public void setTestFilter(String testFilter) { this.testFilter = testFilter; }
    
    public String getTestSkip() { return testSkip; }
    public void setTestSkip(String testSkip) { this.testSkip = testSkip; }
    
    public float getTimeLimit() { return timeLimit; }
    public void setTimeLimit(float timeLimit) { this.timeLimit = Math.max(0, timeLimit); }
    
    public boolean isUnsafeNaming() { return unsafeNaming; }
    public void setUnsafeNaming(boolean unsafeNaming) { this.unsafeNaming = unsafeNaming; }
    
    public String getWebRoot() { return webRoot; }
    public void setWebRoot(String webRoot) { this.webRoot = webRoot; }
    
    // ==================== Request Extended Getters and Setters ====================
    public String getParamDel() { return paramDel; }
    public void setParamDel(String paramDel) { this.paramDel = paramDel; }
    
    public String getCookieDel() { return cookieDel; }
    public void setCookieDel(String cookieDel) { this.cookieDel = cookieDel; }
    
    public String getLiveCookies() { return liveCookies; }
    public void setLiveCookies(String liveCookies) { this.liveCookies = liveCookies; }
    
    public String getLoadCookies() { return loadCookies; }
    public void setLoadCookies(String loadCookies) { this.loadCookies = loadCookies; }
    
    public boolean isDropSetCookie() { return dropSetCookie; }
    public void setDropSetCookie(boolean dropSetCookie) { this.dropSetCookie = dropSetCookie; }
    
    public boolean isHttp2() { return http2; }
    public void setHttp2(boolean http2) { this.http2 = http2; }
    
    public boolean isHttp10() { return http10; }
    public void setHttp10(boolean http10) { this.http10 = http10; }
    
    public boolean isMobile() { return mobile; }
    public void setMobile(boolean mobile) { this.mobile = mobile; }
    
    public String getAuthType() { return authType; }
    public void setAuthType(String authType) { this.authType = authType; }
    
    public String getAuthCred() { return authCred; }
    public void setAuthCred(String authCred) { this.authCred = authCred; }
    
    public String getAuthFile() { return authFile; }
    public void setAuthFile(String authFile) { this.authFile = authFile; }
    
    public String getAbortCode() { return abortCode; }
    public void setAbortCode(String abortCode) { this.abortCode = abortCode; }
    
    public String getIgnoreCode() { return ignoreCode; }
    public void setIgnoreCode(String ignoreCode) { this.ignoreCode = ignoreCode; }
    
    public boolean isIgnoreProxy() { return ignoreProxy; }
    public void setIgnoreProxy(boolean ignoreProxy) { this.ignoreProxy = ignoreProxy; }
    
    public boolean isIgnoreRedirects() { return ignoreRedirects; }
    public void setIgnoreRedirects(boolean ignoreRedirects) { this.ignoreRedirects = ignoreRedirects; }
    
    public boolean isIgnoreTimeouts() { return ignoreTimeouts; }
    public void setIgnoreTimeouts(boolean ignoreTimeouts) { this.ignoreTimeouts = ignoreTimeouts; }
    
    public String getProxyFile() { return proxyFile; }
    public void setProxyFile(String proxyFile) { this.proxyFile = proxyFile; }
    
    public int getProxyFreq() { return proxyFreq; }
    public void setProxyFreq(int proxyFreq) { this.proxyFreq = Math.max(0, proxyFreq); }
    
    public int getTorPort() { return torPort; }
    public void setTorPort(int torPort) { this.torPort = Math.max(1, Math.min(65535, torPort)); }
    
    public String getTorType() { return torType; }
    public void setTorType(String torType) { this.torType = torType; }
    
    public boolean isCheckTor() { return checkTor; }
    public void setCheckTor(boolean checkTor) { this.checkTor = checkTor; }
    
    public String getRetryOn() { return retryOn; }
    public void setRetryOn(String retryOn) { this.retryOn = retryOn; }
    
    public String getRParam() { return rParam; }
    public void setRParam(String rParam) { this.rParam = rParam; }
    
    public String getSafeUrl() { return safeUrl; }
    public void setSafeUrl(String safeUrl) { this.safeUrl = safeUrl; }
    
    public String getSafePost() { return safePost; }
    public void setSafePost(String safePost) { this.safePost = safePost; }
    
    public String getSafeReqFile() { return safeReqFile; }
    public void setSafeReqFile(String safeReqFile) { this.safeReqFile = safeReqFile; }
    
    public int getSafeFreq() { return safeFreq; }
    public void setSafeFreq(int safeFreq) { this.safeFreq = Math.max(0, safeFreq); }
    
    public String getCsrfToken() { return csrfToken; }
    public void setCsrfToken(String csrfToken) { this.csrfToken = csrfToken; }
    
    public String getCsrfUrl() { return csrfUrl; }
    public void setCsrfUrl(String csrfUrl) { this.csrfUrl = csrfUrl; }
    
    public String getCsrfMethod() { return csrfMethod; }
    public void setCsrfMethod(String csrfMethod) { this.csrfMethod = csrfMethod; }
    
    public String getCsrfData() { return csrfData; }
    public void setCsrfData(String csrfData) { this.csrfData = csrfData; }
    
    public int getCsrfRetries() { return csrfRetries; }
    public void setCsrfRetries(int csrfRetries) { this.csrfRetries = Math.max(0, csrfRetries); }
    
    public boolean isChunked() { return chunked; }
    public void setChunked(boolean chunked) { this.chunked = chunked; }
    
    public boolean isHpp() { return hpp; }
    public void setHpp(boolean hpp) { this.hpp = hpp; }
    
    public String getEvalCode() { return evalCode; }
    public void setEvalCode(String evalCode) { this.evalCode = evalCode; }
    
    // ==================== Optimization Extended Getters and Setters ====================
    public boolean isPredictOutput() { return predictOutput; }
    public void setPredictOutput(boolean predictOutput) { this.predictOutput = predictOutput; }
    
    // ==================== Injection Extended Getters and Setters ====================
    public String getParamFilter() { return paramFilter; }
    public void setParamFilter(String paramFilter) { this.paramFilter = paramFilter; }
    
    public String getDbmsCred() { return dbmsCred; }
    public void setDbmsCred(String dbmsCred) { this.dbmsCred = dbmsCred; }
    
    public boolean isInvalidBignum() { return invalidBignum; }
    public void setInvalidBignum(boolean invalidBignum) { this.invalidBignum = invalidBignum; }
    
    public boolean isInvalidLogical() { return invalidLogical; }
    public void setInvalidLogical(boolean invalidLogical) { this.invalidLogical = invalidLogical; }
    
    public boolean isInvalidString() { return invalidString; }
    public void setInvalidString(boolean invalidString) { this.invalidString = invalidString; }
    
    public boolean isNoCast() { return noCast; }
    public void setNoCast(boolean noCast) { this.noCast = noCast; }
    
    public boolean isNoEscape() { return noEscape; }
    public void setNoEscape(boolean noEscape) { this.noEscape = noEscape; }
    
    // ==================== Techniques Extended Getters and Setters ====================
    public boolean isDisableStats() { return disableStats; }
    public void setDisableStats(boolean disableStats) { this.disableStats = disableStats; }
    
    public String getUCols() { return uCols; }
    public void setUCols(String uCols) { this.uCols = uCols; }
    
    public String getUChar() { return uChar; }
    public void setUChar(String uChar) { this.uChar = uChar; }
    
    public String getUFrom() { return uFrom; }
    public void setUFrom(String uFrom) { this.uFrom = uFrom; }
    
    public String getUValues() { return uValues; }
    public void setUValues(String uValues) { this.uValues = uValues; }
    
    public String getDnsDomain() { return dnsDomain; }
    public void setDnsDomain(String dnsDomain) { this.dnsDomain = dnsDomain; }
    
    public String getSecondUrl() { return secondUrl; }
    public void setSecondUrl(String secondUrl) { this.secondUrl = secondUrl; }
    
    public String getSecondReq() { return secondReq; }
    public void setSecondReq(String secondReq) { this.secondReq = secondReq; }
    
    // ==================== Fingerprint Extended Getters and Setters ====================
    public boolean isExtensiveFp() { return extensiveFp; }
    public void setExtensiveFp(boolean extensiveFp) { this.extensiveFp = extensiveFp; }
    
    // ==================== Enumeration Extended Getters and Setters ====================
    public boolean isGetAll() { return getAll; }
    public void setGetAll(boolean getAll) { this.getAll = getAll; }
    
    public boolean isGetHostname() { return getHostname; }
    public void setGetHostname(boolean getHostname) { this.getHostname = getHostname; }
    
    public boolean isGetPasswords() { return getPasswords; }
    public void setGetPasswords(boolean getPasswords) { this.getPasswords = getPasswords; }
    
    public boolean isGetPrivileges() { return getPrivileges; }
    public void setGetPrivileges(boolean getPrivileges) { this.getPrivileges = getPrivileges; }
    
    public boolean isGetRoles() { return getRoles; }
    public void setGetRoles(boolean getRoles) { this.getRoles = getRoles; }
    
    public boolean isGetSchema() { return getSchema; }
    public void setGetSchema(boolean getSchema) { this.getSchema = getSchema; }
    
    public boolean isGetCount() { return getCount; }
    public void setGetCount(boolean getCount) { this.getCount = getCount; }
    
    public boolean isSearch() { return search; }
    public void setSearch(boolean search) { this.search = search; }
    
    public boolean isGetComments() { return getComments; }
    public void setGetComments(boolean getComments) { this.getComments = getComments; }
    
    public boolean isGetStatements() { return getStatements; }
    public void setGetStatements(boolean getStatements) { this.getStatements = getStatements; }
    
    public String getExclude() { return exclude; }
    public void setExclude(String exclude) { this.exclude = exclude; }
    
    public String getPivotColumn() { return pivotColumn; }
    public void setPivotColumn(String pivotColumn) { this.pivotColumn = pivotColumn; }
    
    public String getDumpWhere() { return dumpWhere; }
    public void setDumpWhere(String dumpWhere) { this.dumpWhere = dumpWhere; }
    
    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }
    
    public boolean isExcludeSysDbs() { return excludeSysDbs; }
    public void setExcludeSysDbs(boolean excludeSysDbs) { this.excludeSysDbs = excludeSysDbs; }
    
    public int getLimitStart() { return limitStart; }
    public void setLimitStart(int limitStart) { this.limitStart = Math.max(0, limitStart); }
    
    public int getLimitStop() { return limitStop; }
    public void setLimitStop(int limitStop) { this.limitStop = Math.max(0, limitStop); }
    
    public int getFirstChar() { return firstChar; }
    public void setFirstChar(int firstChar) { this.firstChar = Math.max(0, firstChar); }
    
    public int getLastChar() { return lastChar; }
    public void setLastChar(int lastChar) { this.lastChar = Math.max(0, lastChar); }
    
    public String getSqlQuery() { return sqlQuery; }
    public void setSqlQuery(String sqlQuery) { this.sqlQuery = sqlQuery; }
    
    public boolean isSqlShell() { return sqlShell; }
    public void setSqlShell(boolean sqlShell) { this.sqlShell = sqlShell; }
    
    public String getSqlFile() { return sqlFile; }
    public void setSqlFile(String sqlFile) { this.sqlFile = sqlFile; }
    
    // ==================== Brute force Getters and Setters ====================
    public boolean isCommonTables() { return commonTables; }
    public void setCommonTables(boolean commonTables) { this.commonTables = commonTables; }
    
    public boolean isCommonColumns() { return commonColumns; }
    public void setCommonColumns(boolean commonColumns) { this.commonColumns = commonColumns; }
    
    public boolean isCommonFiles() { return commonFiles; }
    public void setCommonFiles(boolean commonFiles) { this.commonFiles = commonFiles; }
    
    // ==================== UDF Getters and Setters ====================
    public boolean isUdfInject() { return udfInject; }
    public void setUdfInject(boolean udfInject) { this.udfInject = udfInject; }
    
    public String getShLib() { return shLib; }
    public void setShLib(String shLib) { this.shLib = shLib; }
    
    // ==================== File system Getters and Setters ====================
    public String getFileRead() { return fileRead; }
    public void setFileRead(String fileRead) { this.fileRead = fileRead; }
    
    public String getFileWrite() { return fileWrite; }
    public void setFileWrite(String fileWrite) { this.fileWrite = fileWrite; }
    
    public String getFileDest() { return fileDest; }
    public void setFileDest(String fileDest) { this.fileDest = fileDest; }
    
    // ==================== OS takeover Getters and Setters ====================
    public String getOsCmd() { return osCmd; }
    public void setOsCmd(String osCmd) { this.osCmd = osCmd; }
    
    public boolean isOsPwn() { return osPwn; }
    public void setOsPwn(boolean osPwn) { this.osPwn = osPwn; }
    
    public boolean isOsSmb() { return osSmb; }
    public void setOsSmb(boolean osSmb) { this.osSmb = osSmb; }
    
    public boolean isOsBof() { return osBof; }
    public void setOsBof(boolean osBof) { this.osBof = osBof; }
    
    public boolean isPrivEsc() { return privEsc; }
    public void setPrivEsc(boolean privEsc) { this.privEsc = privEsc; }
    
    public String getMsfPath() { return msfPath; }
    public void setMsfPath(String msfPath) { this.msfPath = msfPath; }
    
    public String getTmpPath() { return tmpPath; }
    public void setTmpPath(String tmpPath) { this.tmpPath = tmpPath; }
    
    // ==================== Windows registry Getters and Setters ====================
    public boolean isRegRead() { return regRead; }
    public void setRegRead(boolean regRead) { this.regRead = regRead; }
    
    public boolean isRegAdd() { return regAdd; }
    public void setRegAdd(boolean regAdd) { this.regAdd = regAdd; }
    
    public boolean isRegDel() { return regDel; }
    public void setRegDel(boolean regDel) { this.regDel = regDel; }
    
    public String getRegKey() { return regKey; }
    public void setRegKey(String regKey) { this.regKey = regKey; }
    
    public String getRegVal() { return regVal; }
    public void setRegVal(String regVal) { this.regVal = regVal; }
    
    public String getRegData() { return regData; }
    public void setRegData(String regData) { this.regData = regData; }
    
    public String getRegType() { return regType; }
    public void setRegType(String regType) { this.regType = regType; }
    
    // ==================== Miscellaneous Getters and Setters ====================
    public String getAlert() { return alert; }
    public void setAlert(String alert) { this.alert = alert; }
    
    public boolean isBeep() { return beep; }
    public void setBeep(boolean beep) { this.beep = beep; }
    
    public boolean isDependencies() { return dependencies; }
    public void setDependencies(boolean dependencies) { this.dependencies = dependencies; }
    
    public boolean isDisableColoring() { return disableColoring; }
    public void setDisableColoring(boolean disableColoring) { this.disableColoring = disableColoring; }
    
    public boolean isDisableHashing() { return disableHashing; }
    public void setDisableHashing(boolean disableHashing) { this.disableHashing = disableHashing; }
    
    public boolean isListTampers() { return listTampers; }
    public void setListTampers(boolean listTampers) { this.listTampers = listTampers; }
    
    public boolean isNoLogging() { return noLogging; }
    public void setNoLogging(boolean noLogging) { this.noLogging = noLogging; }
    
    public boolean isNoTruncate() { return noTruncate; }
    public void setNoTruncate(boolean noTruncate) { this.noTruncate = noTruncate; }
    
    public boolean isOffline() { return offline; }
    public void setOffline(boolean offline) { this.offline = offline; }
    
    public boolean isPurge() { return purge; }
    public void setPurge(boolean purge) { this.purge = purge; }
    
    public String getResultsFile() { return resultsFile; }
    public void setResultsFile(String resultsFile) { this.resultsFile = resultsFile; }
    
    public String getTmpDir() { return tmpDir; }
    public void setTmpDir(String tmpDir) { this.tmpDir = tmpDir; }
    
    public boolean isUnstable() { return unstable; }
    public void setUnstable(boolean unstable) { this.unstable = unstable; }
    
    public String getMnemonics() { return mnemonics; }
    public void setMnemonics(String mnemonics) { this.mnemonics = mnemonics; }
    
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
        
        // Target
        if (!direct.isEmpty()) options.put("direct", direct);
        if (!logFile.isEmpty()) options.put("logFile", logFile);
        if (!bulkFile.isEmpty()) options.put("bulkFile", bulkFile);
        if (!sessionFile.isEmpty()) options.put("sessionFile", sessionFile);
        if (!googleDork.isEmpty()) options.put("googleDork", googleDork);
        if (!configFile.isEmpty()) options.put("configFile", configFile);
        
        // General Extended
        if (!trafficFile.isEmpty()) options.put("trafficFile", trafficFile);
        if (abortOnEmpty) options.put("abortOnEmpty", true);
        if (!answers.isEmpty()) options.put("answers", answers);
        if (!base64Parameter.isEmpty()) options.put("base64Parameter", base64Parameter);
        if (base64Safe) options.put("base64Safe", true);
        if (!binaryFields.isEmpty()) options.put("binaryFields", binaryFields);
        if (!charset.isEmpty()) options.put("charset", charset);
        if (checkInternet) options.put("checkInternet", true);
        if (cleanup) options.put("cleanup", true);
        if (!crawlExclude.isEmpty()) options.put("crawlExclude", crawlExclude);
        if (!csvDel.isEmpty()) options.put("csvDel", csvDel);
        if (!dumpFile.isEmpty()) options.put("dumpFile", dumpFile);
        if (!dumpFormat.isEmpty()) options.put("dumpFormat", dumpFormat);
        if (!encoding.isEmpty()) options.put("encoding", encoding);
        if (googlePage > 0) options.put("googlePage", googlePage);
        if (!harFile.isEmpty()) options.put("harFile", harFile);
        if (hexConvert) options.put("hexConvert", true);
        if (!outputDir.isEmpty()) options.put("outputDir", outputDir);
        if (parseErrors) options.put("parseErrors", true);
        if (!preprocess.isEmpty()) options.put("preprocess", preprocess);
        if (!postprocess.isEmpty()) options.put("postprocess", postprocess);
        if (repair) options.put("repair", true);
        if (!saveConfig.isEmpty()) options.put("saveConfig", saveConfig);
        if (!scope.isEmpty()) options.put("scope", scope);
        if (skipHeuristics) options.put("skipHeuristics", true);
        if (skipWaf) options.put("skipWaf", true);
        if (!tablePrefix.isEmpty()) options.put("tablePrefix", tablePrefix);
        if (!testFilter.isEmpty()) options.put("testFilter", testFilter);
        if (!testSkip.isEmpty()) options.put("testSkip", testSkip);
        if (timeLimit > 0) options.put("timeLimit", timeLimit);
        if (unsafeNaming) options.put("unsafeNaming", true);
        if (!webRoot.isEmpty()) options.put("webRoot", webRoot);
        
        // Request Extended
        if (!paramDel.isEmpty()) options.put("paramDel", paramDel);
        if (!cookieDel.isEmpty()) options.put("cookieDel", cookieDel);
        if (!liveCookies.isEmpty()) options.put("liveCookies", liveCookies);
        if (!loadCookies.isEmpty()) options.put("loadCookies", loadCookies);
        if (dropSetCookie) options.put("dropSetCookie", true);
        if (http2) options.put("http2", true);
        if (http10) options.put("http10", true);
        if (mobile) options.put("mobile", true);
        if (!authType.isEmpty()) options.put("authType", authType);
        if (!authCred.isEmpty()) options.put("authCred", authCred);
        if (!authFile.isEmpty()) options.put("authFile", authFile);
        if (!abortCode.isEmpty()) options.put("abortCode", abortCode);
        if (!ignoreCode.isEmpty()) options.put("ignoreCode", ignoreCode);
        if (ignoreProxy) options.put("ignoreProxy", true);
        if (ignoreRedirects) options.put("ignoreRedirects", true);
        if (ignoreTimeouts) options.put("ignoreTimeouts", true);
        if (!proxyFile.isEmpty()) options.put("proxyFile", proxyFile);
        if (proxyFreq > 0) options.put("proxyFreq", proxyFreq);
        if (torPort != 9050) options.put("torPort", torPort);
        if (!torType.equals("SOCKS5")) options.put("torType", torType);
        if (checkTor) options.put("checkTor", true);
        if (!retryOn.isEmpty()) options.put("retryOn", retryOn);
        if (!rParam.isEmpty()) options.put("rParam", rParam);
        if (!safeUrl.isEmpty()) options.put("safeUrl", safeUrl);
        if (!safePost.isEmpty()) options.put("safePost", safePost);
        if (!safeReqFile.isEmpty()) options.put("safeReqFile", safeReqFile);
        if (safeFreq > 0) options.put("safeFreq", safeFreq);
        if (!csrfToken.isEmpty()) options.put("csrfToken", csrfToken);
        if (!csrfUrl.isEmpty()) options.put("csrfUrl", csrfUrl);
        if (!csrfMethod.isEmpty()) options.put("csrfMethod", csrfMethod);
        if (!csrfData.isEmpty()) options.put("csrfData", csrfData);
        if (csrfRetries > 0) options.put("csrfRetries", csrfRetries);
        if (chunked) options.put("chunked", true);
        if (hpp) options.put("hpp", true);
        if (!evalCode.isEmpty()) options.put("evalCode", evalCode);
        
        // Optimization Extended
        if (predictOutput) options.put("predictOutput", true);
        
        // Injection Extended
        if (!paramFilter.isEmpty()) options.put("paramFilter", paramFilter);
        if (!dbmsCred.isEmpty()) options.put("dbmsCred", dbmsCred);
        if (invalidBignum) options.put("invalidBignum", true);
        if (invalidLogical) options.put("invalidLogical", true);
        if (invalidString) options.put("invalidString", true);
        if (noCast) options.put("noCast", true);
        if (noEscape) options.put("noEscape", true);
        
        // Techniques Extended
        if (disableStats) options.put("disableStats", true);
        if (!uCols.isEmpty()) options.put("uCols", uCols);
        if (!uChar.isEmpty()) options.put("uChar", uChar);
        if (!uFrom.isEmpty()) options.put("uFrom", uFrom);
        if (!uValues.isEmpty()) options.put("uValues", uValues);
        if (!dnsDomain.isEmpty()) options.put("dnsDomain", dnsDomain);
        if (!secondUrl.isEmpty()) options.put("secondUrl", secondUrl);
        if (!secondReq.isEmpty()) options.put("secondReq", secondReq);
        
        // Fingerprint Extended
        if (extensiveFp) options.put("extensiveFp", true);
        
        // Enumeration Extended
        if (getAll) options.put("getAll", true);
        if (getHostname) options.put("getHostname", true);
        if (getPasswords) options.put("getPasswords", true);
        if (getPrivileges) options.put("getPrivileges", true);
        if (getRoles) options.put("getRoles", true);
        if (getSchema) options.put("getSchema", true);
        if (getCount) options.put("getCount", true);
        if (search) options.put("search", true);
        if (getComments) options.put("getComments", true);
        if (getStatements) options.put("getStatements", true);
        if (!exclude.isEmpty()) options.put("exclude", exclude);
        if (!pivotColumn.isEmpty()) options.put("pivotColumn", pivotColumn);
        if (!dumpWhere.isEmpty()) options.put("dumpWhere", dumpWhere);
        if (!user.isEmpty()) options.put("user", user);
        if (excludeSysDbs) options.put("excludeSysDbs", true);
        if (limitStart > 0) options.put("limitStart", limitStart);
        if (limitStop > 0) options.put("limitStop", limitStop);
        if (firstChar > 0) options.put("firstChar", firstChar);
        if (lastChar > 0) options.put("lastChar", lastChar);
        if (!sqlQuery.isEmpty()) options.put("sqlQuery", sqlQuery);
        if (sqlShell) options.put("sqlShell", true);
        if (!sqlFile.isEmpty()) options.put("sqlFile", sqlFile);
        
        // Brute force
        if (commonTables) options.put("commonTables", true);
        if (commonColumns) options.put("commonColumns", true);
        if (commonFiles) options.put("commonFiles", true);
        
        // UDF
        if (udfInject) options.put("udfInject", true);
        if (!shLib.isEmpty()) options.put("shLib", shLib);
        
        // File system
        if (!fileRead.isEmpty()) options.put("fileRead", fileRead);
        if (!fileWrite.isEmpty()) options.put("fileWrite", fileWrite);
        if (!fileDest.isEmpty()) options.put("fileDest", fileDest);
        
        // OS takeover
        if (!osCmd.isEmpty()) options.put("osCmd", osCmd);
        if (osPwn) options.put("osPwn", true);
        if (osSmb) options.put("osSmb", true);
        if (osBof) options.put("osBof", true);
        if (privEsc) options.put("privEsc", true);
        if (!msfPath.isEmpty()) options.put("msfPath", msfPath);
        if (!tmpPath.isEmpty()) options.put("tmpPath", tmpPath);
        
        // Windows registry
        if (regRead) options.put("regRead", true);
        if (regAdd) options.put("regAdd", true);
        if (regDel) options.put("regDel", true);
        if (!regKey.isEmpty()) options.put("regKey", regKey);
        if (!regVal.isEmpty()) options.put("regVal", regVal);
        if (!regData.isEmpty()) options.put("regData", regData);
        if (!regType.isEmpty()) options.put("regType", regType);
        
        // Miscellaneous
        if (!alert.isEmpty()) options.put("alert", alert);
        if (beep) options.put("beep", true);
        if (dependencies) options.put("dependencies", true);
        if (disableColoring) options.put("disableColoring", true);
        if (disableHashing) options.put("disableHashing", true);
        if (listTampers) options.put("listTampers", true);
        if (noLogging) options.put("noLogging", true);
        if (noTruncate) options.put("noTruncate", true);
        if (offline) options.put("offline", true);
        if (purge) options.put("purge", true);
        if (!resultsFile.isEmpty()) options.put("resultsFile", resultsFile);
        if (!tmpDir.isEmpty()) options.put("tmpDir", tmpDir);
        if (unstable) options.put("unstable", true);
        if (!mnemonics.isEmpty()) options.put("mnemonics", mnemonics);
        
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
        
        // Target
        copy.direct = this.direct;
        copy.logFile = this.logFile;
        copy.bulkFile = this.bulkFile;
        copy.sessionFile = this.sessionFile;
        copy.googleDork = this.googleDork;
        copy.configFile = this.configFile;
        
        // General Extended
        copy.trafficFile = this.trafficFile;
        copy.abortOnEmpty = this.abortOnEmpty;
        copy.answers = this.answers;
        copy.base64Parameter = this.base64Parameter;
        copy.base64Safe = this.base64Safe;
        copy.binaryFields = this.binaryFields;
        copy.charset = this.charset;
        copy.checkInternet = this.checkInternet;
        copy.cleanup = this.cleanup;
        copy.crawlExclude = this.crawlExclude;
        copy.csvDel = this.csvDel;
        copy.dumpFile = this.dumpFile;
        copy.dumpFormat = this.dumpFormat;
        copy.encoding = this.encoding;
        copy.googlePage = this.googlePage;
        copy.harFile = this.harFile;
        copy.hexConvert = this.hexConvert;
        copy.outputDir = this.outputDir;
        copy.parseErrors = this.parseErrors;
        copy.preprocess = this.preprocess;
        copy.postprocess = this.postprocess;
        copy.repair = this.repair;
        copy.saveConfig = this.saveConfig;
        copy.scope = this.scope;
        copy.skipHeuristics = this.skipHeuristics;
        copy.skipWaf = this.skipWaf;
        copy.tablePrefix = this.tablePrefix;
        copy.testFilter = this.testFilter;
        copy.testSkip = this.testSkip;
        copy.timeLimit = this.timeLimit;
        copy.unsafeNaming = this.unsafeNaming;
        copy.webRoot = this.webRoot;
        
        // Request Extended
        copy.paramDel = this.paramDel;
        copy.cookieDel = this.cookieDel;
        copy.liveCookies = this.liveCookies;
        copy.loadCookies = this.loadCookies;
        copy.dropSetCookie = this.dropSetCookie;
        copy.http2 = this.http2;
        copy.http10 = this.http10;
        copy.mobile = this.mobile;
        copy.authType = this.authType;
        copy.authCred = this.authCred;
        copy.authFile = this.authFile;
        copy.abortCode = this.abortCode;
        copy.ignoreCode = this.ignoreCode;
        copy.ignoreProxy = this.ignoreProxy;
        copy.ignoreRedirects = this.ignoreRedirects;
        copy.ignoreTimeouts = this.ignoreTimeouts;
        copy.proxyFile = this.proxyFile;
        copy.proxyFreq = this.proxyFreq;
        copy.torPort = this.torPort;
        copy.torType = this.torType;
        copy.checkTor = this.checkTor;
        copy.retryOn = this.retryOn;
        copy.rParam = this.rParam;
        copy.safeUrl = this.safeUrl;
        copy.safePost = this.safePost;
        copy.safeReqFile = this.safeReqFile;
        copy.safeFreq = this.safeFreq;
        copy.csrfToken = this.csrfToken;
        copy.csrfUrl = this.csrfUrl;
        copy.csrfMethod = this.csrfMethod;
        copy.csrfData = this.csrfData;
        copy.csrfRetries = this.csrfRetries;
        copy.chunked = this.chunked;
        copy.hpp = this.hpp;
        copy.evalCode = this.evalCode;
        
        // Optimization Extended
        copy.predictOutput = this.predictOutput;
        
        // Injection Extended
        copy.paramFilter = this.paramFilter;
        copy.dbmsCred = this.dbmsCred;
        copy.invalidBignum = this.invalidBignum;
        copy.invalidLogical = this.invalidLogical;
        copy.invalidString = this.invalidString;
        copy.noCast = this.noCast;
        copy.noEscape = this.noEscape;
        
        // Techniques Extended
        copy.disableStats = this.disableStats;
        copy.uCols = this.uCols;
        copy.uChar = this.uChar;
        copy.uFrom = this.uFrom;
        copy.uValues = this.uValues;
        copy.dnsDomain = this.dnsDomain;
        copy.secondUrl = this.secondUrl;
        copy.secondReq = this.secondReq;
        
        // Fingerprint Extended
        copy.extensiveFp = this.extensiveFp;
        
        // Enumeration Extended
        copy.getAll = this.getAll;
        copy.getHostname = this.getHostname;
        copy.getPasswords = this.getPasswords;
        copy.getPrivileges = this.getPrivileges;
        copy.getRoles = this.getRoles;
        copy.getSchema = this.getSchema;
        copy.getCount = this.getCount;
        copy.search = this.search;
        copy.getComments = this.getComments;
        copy.getStatements = this.getStatements;
        copy.exclude = this.exclude;
        copy.pivotColumn = this.pivotColumn;
        copy.dumpWhere = this.dumpWhere;
        copy.user = this.user;
        copy.excludeSysDbs = this.excludeSysDbs;
        copy.limitStart = this.limitStart;
        copy.limitStop = this.limitStop;
        copy.firstChar = this.firstChar;
        copy.lastChar = this.lastChar;
        copy.sqlQuery = this.sqlQuery;
        copy.sqlShell = this.sqlShell;
        copy.sqlFile = this.sqlFile;
        
        // Brute force
        copy.commonTables = this.commonTables;
        copy.commonColumns = this.commonColumns;
        copy.commonFiles = this.commonFiles;
        
        // UDF
        copy.udfInject = this.udfInject;
        copy.shLib = this.shLib;
        
        // File system
        copy.fileRead = this.fileRead;
        copy.fileWrite = this.fileWrite;
        copy.fileDest = this.fileDest;
        
        // OS takeover
        copy.osCmd = this.osCmd;
        copy.osPwn = this.osPwn;
        copy.osSmb = this.osSmb;
        copy.osBof = this.osBof;
        copy.privEsc = this.privEsc;
        copy.msfPath = this.msfPath;
        copy.tmpPath = this.tmpPath;
        
        // Windows registry
        copy.regRead = this.regRead;
        copy.regAdd = this.regAdd;
        copy.regDel = this.regDel;
        copy.regKey = this.regKey;
        copy.regVal = this.regVal;
        copy.regData = this.regData;
        copy.regType = this.regType;
        
        // Miscellaneous
        copy.alert = this.alert;
        copy.beep = this.beep;
        copy.dependencies = this.dependencies;
        copy.disableColoring = this.disableColoring;
        copy.disableHashing = this.disableHashing;
        copy.listTampers = this.listTampers;
        copy.noLogging = this.noLogging;
        copy.noTruncate = this.noTruncate;
        copy.offline = this.offline;
        copy.purge = this.purge;
        copy.resultsFile = this.resultsFile;
        copy.tmpDir = this.tmpDir;
        copy.unstable = this.unstable;
        copy.mnemonics = this.mnemonics;
        
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
        
        // Target
        if (!direct.isEmpty()) sb.append("-d=").append(direct).append(" ");
        if (!logFile.isEmpty()) sb.append("-l=").append(logFile).append(" ");
        if (!bulkFile.isEmpty()) sb.append("-m=").append(bulkFile).append(" ");
        if (!sessionFile.isEmpty()) sb.append("-s=").append(sessionFile).append(" ");
        if (!googleDork.isEmpty()) sb.append("-g=").append(googleDork).append(" ");
        if (!configFile.isEmpty()) sb.append("-c=").append(configFile).append(" ");
        
        // General Extended
        if (!trafficFile.isEmpty()) sb.append("-t=").append(trafficFile).append(" ");
        if (abortOnEmpty) sb.append("--abort-on-empty ");
        if (!answers.isEmpty()) sb.append("--answers=").append(answers).append(" ");
        if (!base64Parameter.isEmpty()) sb.append("--base64=").append(base64Parameter).append(" ");
        if (base64Safe) sb.append("--base64-safe ");
        if (!binaryFields.isEmpty()) sb.append("--binary-fields=").append(binaryFields).append(" ");
        if (!charset.isEmpty()) sb.append("--charset=").append(charset).append(" ");
        if (checkInternet) sb.append("--check-internet ");
        if (cleanup) sb.append("--cleanup ");
        if (!crawlExclude.isEmpty()) sb.append("--crawl-exclude=").append(crawlExclude).append(" ");
        if (!csvDel.isEmpty()) sb.append("--csv-del=").append(csvDel).append(" ");
        if (!dumpFile.isEmpty()) sb.append("--dump-file=").append(dumpFile).append(" ");
        if (!dumpFormat.isEmpty()) sb.append("--dump-format=").append(dumpFormat).append(" ");
        if (!encoding.isEmpty()) sb.append("--encoding=").append(encoding).append(" ");
        if (googlePage > 0) sb.append("--gpage=").append(googlePage).append(" ");
        if (!harFile.isEmpty()) sb.append("--har=").append(harFile).append(" ");
        if (hexConvert) sb.append("--hex ");
        if (!outputDir.isEmpty()) sb.append("--output-dir=").append(outputDir).append(" ");
        if (parseErrors) sb.append("--parse-errors ");
        if (!preprocess.isEmpty()) sb.append("--preprocess=").append(preprocess).append(" ");
        if (!postprocess.isEmpty()) sb.append("--postprocess=").append(postprocess).append(" ");
        if (repair) sb.append("--repair ");
        if (!saveConfig.isEmpty()) sb.append("--save=").append(saveConfig).append(" ");
        if (!scope.isEmpty()) sb.append("--scope=").append(scope).append(" ");
        if (skipHeuristics) sb.append("--skip-heuristics ");
        if (skipWaf) sb.append("--skip-waf ");
        if (!tablePrefix.isEmpty()) sb.append("--table-prefix=").append(tablePrefix).append(" ");
        if (!testFilter.isEmpty()) sb.append("--test-filter=").append(testFilter).append(" ");
        if (!testSkip.isEmpty()) sb.append("--test-skip=").append(testSkip).append(" ");
        if (timeLimit > 0) sb.append("--time-limit=").append(timeLimit).append(" ");
        if (unsafeNaming) sb.append("--unsafe-naming ");
        if (!webRoot.isEmpty()) sb.append("--web-root=").append(webRoot).append(" ");
        
        // Request Extended
        if (!paramDel.isEmpty()) sb.append("--param-del=").append(paramDel).append(" ");
        if (!cookieDel.isEmpty()) sb.append("--cookie-del=").append(cookieDel).append(" ");
        if (!liveCookies.isEmpty()) sb.append("--live-cookies=").append(liveCookies).append(" ");
        if (!loadCookies.isEmpty()) sb.append("--load-cookies=").append(loadCookies).append(" ");
        if (dropSetCookie) sb.append("--drop-set-cookie ");
        if (http2) sb.append("--http2 ");
        if (http10) sb.append("--http1.0 ");
        if (mobile) sb.append("--mobile ");
        if (!authType.isEmpty()) sb.append("--auth-type=").append(authType).append(" ");
        if (!authCred.isEmpty()) sb.append("--auth-cred=").append(authCred).append(" ");
        if (!authFile.isEmpty()) sb.append("--auth-file=").append(authFile).append(" ");
        if (!abortCode.isEmpty()) sb.append("--abort-code=").append(abortCode).append(" ");
        if (!ignoreCode.isEmpty()) sb.append("--ignore-code=").append(ignoreCode).append(" ");
        if (ignoreProxy) sb.append("--ignore-proxy ");
        if (ignoreRedirects) sb.append("--ignore-redirects ");
        if (ignoreTimeouts) sb.append("--ignore-timeouts ");
        if (!proxyFile.isEmpty()) sb.append("--proxy-file=").append(proxyFile).append(" ");
        if (proxyFreq > 0) sb.append("--proxy-freq=").append(proxyFreq).append(" ");
        if (torPort != 9050) sb.append("--tor-port=").append(torPort).append(" ");
        if (!torType.equals("SOCKS5")) sb.append("--tor-type=").append(torType).append(" ");
        if (checkTor) sb.append("--check-tor ");
        if (!retryOn.isEmpty()) sb.append("--retry-on=").append(retryOn).append(" ");
        if (!rParam.isEmpty()) sb.append("--randomize=").append(rParam).append(" ");
        if (!safeUrl.isEmpty()) sb.append("--safe-url=").append(safeUrl).append(" ");
        if (!safePost.isEmpty()) sb.append("--safe-post=").append(safePost).append(" ");
        if (!safeReqFile.isEmpty()) sb.append("--safe-req=").append(safeReqFile).append(" ");
        if (safeFreq > 0) sb.append("--safe-freq=").append(safeFreq).append(" ");
        if (!csrfToken.isEmpty()) sb.append("--csrf-token=").append(csrfToken).append(" ");
        if (!csrfUrl.isEmpty()) sb.append("--csrf-url=").append(csrfUrl).append(" ");
        if (!csrfMethod.isEmpty()) sb.append("--csrf-method=").append(csrfMethod).append(" ");
        if (!csrfData.isEmpty()) sb.append("--csrf-data=").append(csrfData).append(" ");
        if (csrfRetries > 0) sb.append("--csrf-retries=").append(csrfRetries).append(" ");
        if (chunked) sb.append("--chunked ");
        if (hpp) sb.append("--hpp ");
        if (!evalCode.isEmpty()) sb.append("--eval=").append(evalCode).append(" ");
        
        // Optimization Extended
        if (predictOutput) sb.append("--predict-output ");
        
        // Injection Extended
        if (!paramFilter.isEmpty()) sb.append("--param-filter=").append(paramFilter).append(" ");
        if (!dbmsCred.isEmpty()) sb.append("--dbms-cred=").append(dbmsCred).append(" ");
        if (invalidBignum) sb.append("--invalid-bignum ");
        if (invalidLogical) sb.append("--invalid-logical ");
        if (invalidString) sb.append("--invalid-string ");
        if (noCast) sb.append("--no-cast ");
        if (noEscape) sb.append("--no-escape ");
        
        // Techniques Extended
        if (disableStats) sb.append("--disable-stats ");
        if (!uCols.isEmpty()) sb.append("--union-cols=").append(uCols).append(" ");
        if (!uChar.isEmpty()) sb.append("--union-char=").append(uChar).append(" ");
        if (!uFrom.isEmpty()) sb.append("--union-from=").append(uFrom).append(" ");
        if (!uValues.isEmpty()) sb.append("--union-values=").append(uValues).append(" ");
        if (!dnsDomain.isEmpty()) sb.append("--dns-domain=").append(dnsDomain).append(" ");
        if (!secondUrl.isEmpty()) sb.append("--second-url=").append(secondUrl).append(" ");
        if (!secondReq.isEmpty()) sb.append("--second-req=").append(secondReq).append(" ");
        
        // Fingerprint Extended
        if (extensiveFp) sb.append("-f ");
        
        // Enumeration Extended
        if (getAll) sb.append("-a ");
        if (getHostname) sb.append("--hostname ");
        if (getPasswords) sb.append("--passwords ");
        if (getPrivileges) sb.append("--privileges ");
        if (getRoles) sb.append("--roles ");
        if (getSchema) sb.append("--schema ");
        if (getCount) sb.append("--count ");
        if (search) sb.append("--search ");
        if (getComments) sb.append("--comments ");
        if (getStatements) sb.append("--statements ");
        if (!exclude.isEmpty()) sb.append("-X=").append(exclude).append(" ");
        if (!pivotColumn.isEmpty()) sb.append("--pivot-column=").append(pivotColumn).append(" ");
        if (!dumpWhere.isEmpty()) sb.append("--where=").append(dumpWhere).append(" ");
        if (!user.isEmpty()) sb.append("-U=").append(user).append(" ");
        if (excludeSysDbs) sb.append("--exclude-sysdbs ");
        if (limitStart > 0) sb.append("--start=").append(limitStart).append(" ");
        if (limitStop > 0) sb.append("--stop=").append(limitStop).append(" ");
        if (firstChar > 0) sb.append("--first=").append(firstChar).append(" ");
        if (lastChar > 0) sb.append("--last=").append(lastChar).append(" ");
        if (!sqlQuery.isEmpty()) sb.append("--sql-query=").append(sqlQuery).append(" ");
        if (sqlShell) sb.append("--sql-shell ");
        if (!sqlFile.isEmpty()) sb.append("--sql-file=").append(sqlFile).append(" ");
        
        // Brute force
        if (commonTables) sb.append("--common-tables ");
        if (commonColumns) sb.append("--common-columns ");
        if (commonFiles) sb.append("--common-files ");
        
        // UDF
        if (udfInject) sb.append("--udf-inject ");
        if (!shLib.isEmpty()) sb.append("--shared-lib=").append(shLib).append(" ");
        
        // File system
        if (!fileRead.isEmpty()) sb.append("--file-read=").append(fileRead).append(" ");
        if (!fileWrite.isEmpty()) sb.append("--file-write=").append(fileWrite).append(" ");
        if (!fileDest.isEmpty()) sb.append("--file-dest=").append(fileDest).append(" ");
        
        // OS takeover
        if (!osCmd.isEmpty()) sb.append("--os-cmd=").append(osCmd).append(" ");
        if (osPwn) sb.append("--os-pwn ");
        if (osSmb) sb.append("--os-smbrelay ");
        if (osBof) sb.append("--os-bof ");
        if (privEsc) sb.append("--priv-esc ");
        if (!msfPath.isEmpty()) sb.append("--msf-path=").append(msfPath).append(" ");
        if (!tmpPath.isEmpty()) sb.append("--tmp-path=").append(tmpPath).append(" ");
        
        // Windows registry
        if (regRead) sb.append("--reg-read ");
        if (regAdd) sb.append("--reg-add ");
        if (regDel) sb.append("--reg-del ");
        if (!regKey.isEmpty()) sb.append("--reg-key=").append(regKey).append(" ");
        if (!regVal.isEmpty()) sb.append("--reg-value=").append(regVal).append(" ");
        if (!regData.isEmpty()) sb.append("--reg-data=").append(regData).append(" ");
        if (!regType.isEmpty()) sb.append("--reg-type=").append(regType).append(" ");
        
        // Miscellaneous
        if (!alert.isEmpty()) sb.append("--alert=").append(alert).append(" ");
        if (beep) sb.append("--beep ");
        if (dependencies) sb.append("--dependencies ");
        if (disableColoring) sb.append("--disable-coloring ");
        if (disableHashing) sb.append("--disable-hashing ");
        if (listTampers) sb.append("--list-tampers ");
        if (noLogging) sb.append("--no-logging ");
        if (noTruncate) sb.append("--no-truncate ");
        if (offline) sb.append("--offline ");
        if (purge) sb.append("--purge ");
        if (!resultsFile.isEmpty()) sb.append("--results-file=").append(resultsFile).append(" ");
        if (!tmpDir.isEmpty()) sb.append("--tmp-dir=").append(tmpDir).append(" ");
        if (unstable) sb.append("--unstable ");
        if (!mnemonics.isEmpty()) sb.append("-z=").append(mnemonics).append(" ");
        
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
