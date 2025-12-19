package com.sqlmapwebui.burp;

import com.google.gson.Gson;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 扫描配置模型
 * 存储SQLMap扫描参数配置
 */
public class ScanConfig {
    
    private String name;
    private String description;
    
    // SQLMap核心选项
    private int level = 1;          // --level (1-5)
    private int risk = 1;           // --risk (1-3)
    private String dbms = "";       // --dbms (MySQL, PostgreSQL, Oracle, etc.)
    private String technique = "";  // --technique (BEUSTQ)
    private String tamper = "";     // --tamper
    
    // 请求选项
    private int timeout = 30;       // --timeout
    private int retries = 3;        // --retries
    private int delay = 0;          // --delay
    private String proxy = "";      // --proxy
    
    // 检测选项
    private boolean textOnly = false;    // --text-only
    private boolean titles = false;      // --titles
    private String string = "";          // --string
    private String notString = "";       // --not-string
    
    // 其他选项
    private boolean batch = true;        // --batch
    private boolean forms = false;       // --forms
    private boolean crawl = false;       // --crawl
    private String cookie = "";          // --cookie
    private String userAgent = "";       // --user-agent
    private String referer = "";         // --referer
    private String headers = "";         // --headers
    private String data = "";            // --data
    private String param = "";           // -p (parameter)
    
    // 创建时间戳
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
    
    public int getLevel() { return level; }
    public void setLevel(int level) { this.level = Math.max(1, Math.min(5, level)); }
    
    public int getRisk() { return risk; }
    public void setRisk(int risk) { this.risk = Math.max(1, Math.min(3, risk)); }
    
    public String getDbms() { return dbms; }
    public void setDbms(String dbms) { this.dbms = dbms; }
    
    public String getTechnique() { return technique; }
    public void setTechnique(String technique) { this.technique = technique; }
    
    public String getTamper() { return tamper; }
    public void setTamper(String tamper) { this.tamper = tamper; }
    
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
    
    public int getRetries() { return retries; }
    public void setRetries(int retries) { this.retries = retries; }
    
    public int getDelay() { return delay; }
    public void setDelay(int delay) { this.delay = delay; }
    
    public String getProxy() { return proxy; }
    public void setProxy(String proxy) { this.proxy = proxy; }
    
    public boolean isTextOnly() { return textOnly; }
    public void setTextOnly(boolean textOnly) { this.textOnly = textOnly; }
    
    public boolean isTitles() { return titles; }
    public void setTitles(boolean titles) { this.titles = titles; }
    
    public String getString() { return string; }
    public void setString(String string) { this.string = string; }
    
    public String getNotString() { return notString; }
    public void setNotString(String notString) { this.notString = notString; }
    
    public boolean isBatch() { return batch; }
    public void setBatch(boolean batch) { this.batch = batch; }
    
    public boolean isForms() { return forms; }
    public void setForms(boolean forms) { this.forms = forms; }
    
    public boolean isCrawl() { return crawl; }
    public void setCrawl(boolean crawl) { this.crawl = crawl; }
    
    public String getCookie() { return cookie; }
    public void setCookie(String cookie) { this.cookie = cookie; }
    
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    
    public String getReferer() { return referer; }
    public void setReferer(String referer) { this.referer = referer; }
    
    public String getHeaders() { return headers; }
    public void setHeaders(String headers) { this.headers = headers; }
    
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
    
    public String getParam() { return param; }
    public void setParam(String param) { this.param = param; }
    
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    
    public long getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(long lastUsedAt) { this.lastUsedAt = lastUsedAt; }
    
    public void updateLastUsed() {
        this.lastUsedAt = System.currentTimeMillis();
    }
    
    /**
     * 转换为提交给后端的options Map
     */
    public Map<String, Object> toOptionsMap() {
        Map<String, Object> options = new HashMap<>();
        
        if (level != 1) options.put("level", level);
        if (risk != 1) options.put("risk", risk);
        if (!dbms.isEmpty()) options.put("dbms", dbms);
        if (!technique.isEmpty()) options.put("technique", technique);
        if (!tamper.isEmpty()) options.put("tamper", tamper);
        if (timeout != 30) options.put("timeout", timeout);
        if (retries != 3) options.put("retries", retries);
        if (delay > 0) options.put("delay", delay);
        if (!proxy.isEmpty()) options.put("proxy", proxy);
        if (textOnly) options.put("textOnly", true);
        if (titles) options.put("titles", true);
        if (!string.isEmpty()) options.put("string", string);
        if (!notString.isEmpty()) options.put("notString", notString);
        options.put("batch", batch);
        if (forms) options.put("forms", true);
        if (crawl) options.put("crawl", true);
        if (!cookie.isEmpty()) options.put("cookie", cookie);
        if (!userAgent.isEmpty()) options.put("agent", userAgent);
        if (!referer.isEmpty()) options.put("referer", referer);
        if (!headers.isEmpty()) options.put("headers", headers);
        if (!data.isEmpty()) options.put("data", data);
        if (!param.isEmpty()) options.put("p", param);
        
        return options;
    }
    
    /**
     * 克隆配置
     */
    public ScanConfig copy() {
        ScanConfig copy = new ScanConfig();
        copy.name = this.name;
        copy.description = this.description;
        copy.level = this.level;
        copy.risk = this.risk;
        copy.dbms = this.dbms;
        copy.technique = this.technique;
        copy.tamper = this.tamper;
        copy.timeout = this.timeout;
        copy.retries = this.retries;
        copy.delay = this.delay;
        copy.proxy = this.proxy;
        copy.textOnly = this.textOnly;
        copy.titles = this.titles;
        copy.string = this.string;
        copy.notString = this.notString;
        copy.batch = this.batch;
        copy.forms = this.forms;
        copy.crawl = this.crawl;
        copy.cookie = this.cookie;
        copy.userAgent = this.userAgent;
        copy.referer = this.referer;
        copy.headers = this.headers;
        copy.data = this.data;
        copy.param = this.param;
        copy.createdAt = System.currentTimeMillis();
        copy.lastUsedAt = copy.createdAt;
        return copy;
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
}
