package com.sqlmapwebui.burp.util;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.jayway.jsonpath.JsonPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 终端窗口标题提取器
 * 从 HTTP 请求中提取标题，支持多种提取方式
 */
public final class TitleExtractor {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(TitleExtractor.class);
    
    private TitleExtractor() {
        throw new AssertionError("TitleExtractor cannot be instantiated");
    }
    
    /**
     * 提取结果信息类（用于测试对话框）
     */
    public static class ExtractionResult {
        private final String title;
        private final String matchedRuleName;
        private final TitleSourceType matchedSourceType;
        
        public ExtractionResult(String title, String matchedRuleName, TitleSourceType matchedSourceType) {
            this.title = title;
            this.matchedRuleName = matchedRuleName;
            this.matchedSourceType = matchedSourceType;
        }
        
        public String getTitle() {
            return title;
        }
        
        public String getMatchedRuleName() {
            return matchedRuleName;
        }
        
        public TitleSourceType getMatchedSourceType() {
            return matchedSourceType;
        }
    }
    
    /**
     * 从 HTTP 请求提取标题
     *
     * @param request HTTP 请求对象
     * @param config  标题配置
     * @return 提取的标题，如果提取失败返回 fallback
     */
    public static String extract(HttpRequest request, TitleConfig config) {
        if (request == null || config == null) {
            return config != null ? config.getFallback() : "SQLMap";
        }
        
        String title = null;
        
        try {
            switch (config.getSourceType()) {
                case URL_PATH:
                    title = extractFromUrlPath(request);
                    break;
                case URL_PATH_SUB:
                    title = extractFromUrlPathSub(request, config);
                    break;
                case FIXED:
                    title = config.getFixedValue();
                    break;
                case REGEX:
                    title = extractFromRegex(request, config);
                    break;
                case JSON_PATH:
                    title = extractFromJsonPath(request, config);
                    break;
                case XPATH:
                    title = extractFromXPath(request, config);
                    break;
                case FORM_FIELD:
                    title = extractFromFormField(request, config);
                    break;
                default:
                    title = extractFromUrlPath(request);
            }
        } catch (Exception e) {
            LOGGER.warn("标题提取失败: {}", e.getMessage());
            title = null;
        }
        
        // 如果提取失败，使用 fallback
        if (title == null || title.trim().isEmpty()) {
            title = config.getFallback();
        }
        
        // 清理和截断标题
        title = sanitizeTitle(title);
        title = truncateTitle(title, config.getMaxLength());
        
        return title;
    }
    
    /**
     * 使用规则列表提取标题（多规则优先级匹配）
     * 按优先级依次尝试每个启用的规则，第一个成功提取的规则生效
     *
     * @param request   HTTP 请求对象
     * @param rules     规则列表
     * @param fallback  全局回退标题
     * @param maxLength 标题最大长度
     * @return 提取的标题
     */
    public static String extract(HttpRequest request, List<TitleRule> rules,
                                 String fallback, int maxLength) {
        if (request == null) {
            return sanitizeAndTruncate(fallback != null ? fallback : "SQLMap", maxLength);
        }
        
        if (rules == null || rules.isEmpty()) {
            // 没有规则，使用默认规则
            return extractByRule(request, TitleRule.createDefaultRule(), fallback, maxLength);
        }
        
        // 按优先级排序启用的规则
        List<TitleRule> sortedEnabledRules = rules.stream()
            .filter(TitleRule::isEnabled)
            .sorted(Comparator.comparingInt(TitleRule::getPriority))
            .toList();
        
        // 依次尝试每个规则
        for (TitleRule rule : sortedEnabledRules) {
            try {
                String title = extractByRule(request, rule, null, maxLength);
                if (title != null && !title.trim().isEmpty()) {
                    LOGGER.debug("规则 '{}' (优先级{}) 提取成功: {}", rule.getName(), rule.getPriority(), title);
                    return title;
                }
            } catch (Exception e) {
                LOGGER.debug("规则 '{}' 提取失败: {}", rule.getName(), e.getMessage());
            }
        }
        
        // 所有规则都失败，使用全局 fallback
        return sanitizeAndTruncate(fallback != null ? fallback : "SQLMap", maxLength);
    }
    
    /**
     * 使用单个规则提取标题
     */
    private static String extractByRule(HttpRequest request, TitleRule rule,
                                         String fallback, int maxLength) {
        if (request == null || rule == null) {
            return sanitizeAndTruncate(fallback != null ? fallback : "SQLMap", maxLength);
        }
        
        String title = null;
        
        try {
            switch (rule.getSourceType()) {
                case URL_PATH:
                    title = extractFromUrlPath(request);
                    break;
                case URL_PATH_SUB:
                    title = extractFromUrlPathSubByRule(request, rule);
                    break;
                case FIXED:
                    title = rule.getFixedValue();
                    break;
                case REGEX:
                    title = extractFromRegexByRule(request, rule);
                    break;
                case JSON_PATH:
                    title = extractFromJsonPathByRule(request, rule);
                    break;
                case XPATH:
                    title = extractFromXPathByRule(request, rule);
                    break;
                case FORM_FIELD:
                    title = extractFromFormFieldByRule(request, rule);
                    break;
                default:
                    title = extractFromUrlPath(request);
            }
        } catch (Exception e) {
            LOGGER.debug("规则 '{}' 提取异常: {}", rule.getName(), e.getMessage());
            title = null;
        }
        
        if (title == null || title.trim().isEmpty()) {
            if (fallback != null) {
                return sanitizeAndTruncate(fallback, maxLength);
            }
            return null;
        }
        
        return sanitizeAndTruncate(title, maxLength);
    }
    
    /**
     * 从 URL 路径子串提取（使用规则参数）
     */
    private static String extractFromUrlPathSubByRule(HttpRequest request, TitleRule rule) {
        try {
            String url = request.url();
            URL parsedUrl = new URL(url);
            String path = parsedUrl.getPath();
            
            if (path.startsWith("/")) {
                path = path.substring(1);
            }
            
            return extractSubstringByRule(path, rule);
        } catch (Exception e) {
            LOGGER.warn("URL路径子串提取失败: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 从正则表达式提取（使用规则参数）
     */
    private static String extractFromRegexByRule(HttpRequest request, TitleRule rule) {
        if (rule.getRegexPattern() == null || rule.getRegexPattern().isEmpty()) {
            return null;
        }
        
        try {
            String content;
            if (rule.getRegexSource() == RegexSource.URL) {
                content = request.url();
            } else if (rule.getRegexSource() == RegexSource.REQUEST_BODY) {
                content = new String(request.body().getBytes(), StandardCharsets.UTF_8);
            } else {
                // FULL_REQUEST
                content = request.toString();
            }
            
            Pattern pattern = Pattern.compile(rule.getRegexPattern());
            Matcher matcher = pattern.matcher(content);
            
            if (matcher.find()) {
                int group = rule.getRegexGroup();
                if (group >= 0 && group <= matcher.groupCount()) {
                    return matcher.group(group);
                } else if (matcher.groupCount() > 0) {
                    return matcher.group(1);
                }
            }
        } catch (Exception e) {
            LOGGER.warn("正则提取失败: {}", e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 从 JSON Path 提取（使用规则参数）
     */
    private static String extractFromJsonPathByRule(HttpRequest request, TitleRule rule) {
        if (rule.getJsonPath() == null || rule.getJsonPath().isEmpty()) {
            return null;
        }
        
        try {
            String body = new String(request.body().getBytes(), StandardCharsets.UTF_8);
            return extractJsonPathValue(body, rule.getJsonPath());
        } catch (Exception e) {
            LOGGER.warn("JSON Path 提取失败: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 从 XPath 提取（使用规则参数）
     */
    private static String extractFromXPathByRule(HttpRequest request, TitleRule rule) {
        if (rule.getXpath() == null || rule.getXpath().isEmpty()) {
            return null;
        }
        
        try {
            String body = new String(request.body().getBytes(), StandardCharsets.UTF_8);
            return extractXPathValue(body, rule.getXpath());
        } catch (Exception e) {
            LOGGER.warn("XPath 提取失败: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 从表单字段提取（使用规则参数）
     */
    private static String extractFromFormFieldByRule(HttpRequest request, TitleRule rule) {
        if (rule.getFormField() == null || rule.getFormField().isEmpty()) {
            return null;
        }
        
        try {
            String body = new String(request.body().getBytes(), StandardCharsets.UTF_8);
            return extractFormFieldValue(body, rule.getFormField());
        } catch (Exception e) {
            LOGGER.warn("表单字段提取失败: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 清理并截断标题
     */
    private static String sanitizeAndTruncate(String title, int maxLength) {
        if (title == null) {
            return null;
        }
        title = sanitizeTitle(title);
        title = truncateTitle(title, maxLength);
        return title;
    }
    
    /**
     * 从原始请求字符串提取标题（用于测试对话框）
     *
     * @param rawRequest 原始请求字符串
     * @param config     标题配置
     * @return 提取的标题
     */
    public static String extractFromRawRequest(String rawRequest, TitleConfig config) {
        if (rawRequest == null || rawRequest.trim().isEmpty()) {
            return config != null ? config.getFallback() : "SQLMap";
        }
        
        String title = null;
        
        try {
            switch (config.getSourceType()) {
                case URL_PATH:
                    title = extractUrlPathFromRawRequest(rawRequest);
                    break;
                case URL_PATH_SUB:
                    String path = extractUrlPathFromRawRequest(rawRequest);
                    title = extractSubstring(path, config);
                    break;
                case FIXED:
                    title = config.getFixedValue();
                    break;
                case REGEX:
                    title = extractFromRegexRaw(rawRequest, config);
                    break;
                case JSON_PATH:
                    String body = extractBodyFromRawRequest(rawRequest);
                    title = extractJsonPathValue(body, config.getJsonPath());
                    break;
                case XPATH:
                    String xmlBody = extractBodyFromRawRequest(rawRequest);
                    title = extractXPathValue(xmlBody, config.getXpath());
                    break;
                case FORM_FIELD:
                    String formBody = extractBodyFromRawRequest(rawRequest);
                    title = extractFormFieldValue(formBody, config.getFormField());
                    break;
                default:
                    title = extractUrlPathFromRawRequest(rawRequest);
            }
        } catch (Exception e) {
            LOGGER.warn("标题提取失败: {}", e.getMessage());
            title = null;
        }
        
        if (title == null || title.trim().isEmpty()) {
            title = config.getFallback();
        }
        
        title = sanitizeTitle(title);
        title = truncateTitle(title, config.getMaxLength());
        
        return title;
    }
    
    // ============ URL 路径提取 ============
    
    /**
     * 从请求中提取 URL 路径的最后一段作为标题
     */
    private static String extractFromUrlPath(HttpRequest request) {
        try {
            String url = request.url();
            URL parsedUrl = new URL(url);
            String path = parsedUrl.getPath();
            
            // 移除开头的 /
            if (path.startsWith("/")) {
                path = path.substring(1);
            }
            
            // 如果路径为空，返回 host
            if (path.isEmpty()) {
                return parsedUrl.getHost();
            }
            
            // 获取最后一段路径
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash >= 0 && lastSlash < path.length() - 1) {
                return path.substring(lastSlash + 1);
            }
            
            return path;
        } catch (Exception e) {
            LOGGER.warn("URL路径提取失败: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 从请求中提取 URL 路径子串作为标题
     */
    private static String extractFromUrlPathSub(HttpRequest request, TitleConfig config) {
        try {
            String url = request.url();
            URL parsedUrl = new URL(url);
            String path = parsedUrl.getPath();
            
            return extractSubstring(path, config);
        } catch (Exception e) {
            LOGGER.warn("URL路径子串提取失败: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 从字符串中提取子串
     */
    private static String extractSubstring(String str, TitleConfig config) {
        if (str == null || str.isEmpty()) {
            return null;
        }
        
        // 移除开头的 /
        if (str.startsWith("/")) {
            str = str.substring(1);
        }
        
        int len = str.length();
        int start = config.parsePathSubStart();
        int end = config.parsePathSubEnd();
        
        // 处理特殊值 -0（表示到结尾）
        if (end == Integer.MIN_VALUE) {
            end = len;
        }
        
        // 处理负数索引
        if (start < 0) {
            start = len + start;
        }
        if (end < 0) {
            end = len + end;
        }
        
        // 边界检查
        start = Math.max(0, Math.min(start, len));
        end = Math.max(0, Math.min(end, len));
        
        // 如果 start >= end，返回 null
        if (start >= end) {
            return null;
        }
        
        return str.substring(start, end);
    }
    
    // ============ 正则表达式提取 ============
    
    /**
     * 使用正则表达式从请求中提取标题
     */
    private static String extractFromRegex(HttpRequest request, TitleConfig config) {
        String content = null;
        
        switch (config.getRegexSource()) {
            case URL:
                content = request.url();
                break;
            case REQUEST_BODY:
                content = getBodyAsUtf8(request);
                break;
            case FULL_REQUEST:
                content = getRequestAsUtf8(request);
                break;
        }
        
        if (content == null || content.isEmpty()) {
            return null;
        }
        
        return extractRegexValue(content, config.getRegexPattern(), config.getRegexGroup());
    }
    
    /**
     * 使用正则表达式从原始请求字符串中提取
     */
    private static String extractFromRegexRaw(String rawRequest, TitleConfig config) {
        String content = null;
        
        switch (config.getRegexSource()) {
            case URL:
                content = extractUrlFromRawRequest(rawRequest);
                break;
            case REQUEST_BODY:
                content = extractBodyFromRawRequest(rawRequest);
                break;
            case FULL_REQUEST:
                content = rawRequest;
                break;
        }
        
        if (content == null || content.isEmpty()) {
            return null;
        }
        
        return extractRegexValue(content, config.getRegexPattern(), config.getRegexGroup());
    }
    
    /**
     * 执行正则匹配并提取指定捕获组
     */
    private static String extractRegexValue(String content, String pattern, int group) {
        if (content == null || pattern == null || pattern.isEmpty()) {
            return null;
        }
        
        try {
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(content);
            
            if (m.find()) {
                if (group <= m.groupCount()) {
                    return m.group(group);
                } else if (m.groupCount() >= 1) {
                    return m.group(1);
                } else {
                    return m.group();
                }
            }
        } catch (Exception e) {
            LOGGER.warn("正则表达式匹配失败: {}", e.getMessage());
        }
        
        return null;
    }
    
    // ============ JSON Path 提取 ============
    
    /**
     * 使用 JSON Path 从请求体中提取标题
     */
    private static String extractFromJsonPath(HttpRequest request, TitleConfig config) {
        String body = getBodyAsUtf8(request);
        return extractJsonPathValue(body, config.getJsonPath());
    }
    
    /**
     * 执行 JSON Path 提取
     */
    private static String extractJsonPathValue(String json, String jsonPath) {
        if (json == null || json.isEmpty() || jsonPath == null || jsonPath.isEmpty()) {
            return null;
        }
        
        // 检查是否是 JSON 格式
        if (!json.trim().startsWith("{") && !json.trim().startsWith("[")) {
            return null;
        }
        
        try {
            Object result = JsonPath.read(json, jsonPath);
            if (result != null) {
                return result.toString();
            }
        } catch (Exception e) {
            LOGGER.warn("JSON Path 提取失败: {}", e.getMessage());
        }
        
        return null;
    }
    
    // ============ XPath 提取 ============
    
    /**
     * 使用 XPath 从请求体中提取标题
     */
    private static String extractFromXPath(HttpRequest request, TitleConfig config) {
        String body = getBodyAsUtf8(request);
        return extractXPathValue(body, config.getXpath());
    }
    
    /**
     * 执行 XPath 提取
     */
    private static String extractXPathValue(String xml, String xpath) {
        if (xml == null || xml.isEmpty() || xpath == null || xpath.isEmpty()) {
            return null;
        }
        
        // 检查是否是 XML 格式
        if (!xml.trim().startsWith("<")) {
            return null;
        }
        
        try {
            javax.xml.xpath.XPathFactory factory = javax.xml.xpath.XPathFactory.newInstance();
            javax.xml.xpath.XPath xpathObj = factory.newXPath();
            
            javax.xml.parsers.DocumentBuilderFactory dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = dbFactory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            
            String result = xpathObj.evaluate(xpath, doc);
            if (result != null && !result.isEmpty()) {
                return result;
            }
        } catch (Exception e) {
            LOGGER.warn("XPath 提取失败: {}", e.getMessage());
        }
        
        return null;
    }
    
    // ============ 表单字段提取 ============
    
    /**
     * 从表单请求体中提取字段值
     */
    private static String extractFromFormField(HttpRequest request, TitleConfig config) {
        // 检查 Content-Type
        String contentType = null;
        for (var header : request.headers()) {
            String headerStr = header.toString();
            if (headerStr.toLowerCase().startsWith("content-type:")) {
                contentType = headerStr.substring("content-type:".length()).trim().toLowerCase();
                break;
            }
        }
        
        if (contentType == null || !contentType.contains("application/x-www-form-urlencoded")) {
            return null;
        }
        
        String body = getBodyAsUtf8(request);
        return extractFormFieldValue(body, config.getFormField());
    }
    
    /**
     * 从表单字符串中提取字段值
     */
    private static String extractFormFieldValue(String formBody, String fieldName) {
        if (formBody == null || formBody.isEmpty() || fieldName == null || fieldName.isEmpty()) {
            return null;
        }
        
        try {
            // 解析表单参数
            Map<String, String> params = parseFormUrlEncoded(formBody);
            return params.get(fieldName);
        } catch (Exception e) {
            LOGGER.warn("表单字段提取失败: {}", e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 解析 form-urlencoded 字符串
     */
    private static Map<String, String> parseFormUrlEncoded(String form) {
        Map<String, String> params = new HashMap<>();
        String[] pairs = form.split("&");
        
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                String key = java.net.URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                String value = eqIdx < pair.length() - 1 
                    ? java.net.URLDecoder.decode(pair.substring(eqIdx + 1), StandardCharsets.UTF_8) 
                    : "";
                params.put(key, value);
            }
        }
        
        return params;
    }
    
    // ============ 工具方法 ============
    
    /**
     * 获取请求体的 UTF-8 字符串
     */
    private static String getBodyAsUtf8(HttpRequest request) {
        try {
            byte[] bodyBytes = request.body().getBytes();
            return new String(bodyBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * 获取完整请求的 UTF-8 字符串
     */
    private static String getRequestAsUtf8(HttpRequest request) {
        try {
            byte[] requestBytes = request.toByteArray().getBytes();
            return new String(requestBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * 从原始请求字符串中提取 URL
     */
    private static String extractUrlFromRawRequest(String rawRequest) {
        try {
            String[] lines = rawRequest.split("\r\n|\n");
            if (lines.length > 0) {
                String requestLine = lines[0];
                String[] parts = requestLine.split(" ");
                if (parts.length >= 2) {
                    return parts[1]; // 返回路径部分
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }
    
    /**
     * 从原始请求字符串中提取 URL 路径
     */
    private static String extractUrlPathFromRawRequest(String rawRequest) {
        String url = extractUrlFromRawRequest(rawRequest);
        if (url == null) {
            return null;
        }
        
        // 移除查询参数
        int queryIdx = url.indexOf('?');
        if (queryIdx > 0) {
            url = url.substring(0, queryIdx);
        }
        
        // 获取最后一段路径
        int lastSlash = url.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < url.length() - 1) {
            return url.substring(lastSlash + 1);
        }
        
        return url;
    }
    
    /**
     * 从原始请求字符串中提取请求体
     */
    private static String extractBodyFromRawRequest(String rawRequest) {
        try {
            // 查找空行分隔符
            int bodyStart = rawRequest.indexOf("\r\n\r\n");
            if (bodyStart < 0) {
                bodyStart = rawRequest.indexOf("\n\n");
                if (bodyStart >= 0) {
                    return rawRequest.substring(bodyStart + 2);
                }
            } else {
                return rawRequest.substring(bodyStart + 4);
            }
        } catch (Exception e) {
            // ignore
        }
        return "";
    }
    
    /**
     * 清理标题中的特殊字符
     */
    private static String sanitizeTitle(String title) {
        if (title == null || title.isEmpty()) {
            return title;
        }
        
        // 移除控制字符
        title = title.replaceAll("[\\x00-\\x1F\\x7F-\\x9F]", "");
        
        // 移除换行和制表符
        title = title.replace("\n", "").replace("\r", "").replace("\t", " ");
        
        // 替换多个空格为单个空格
        title = title.replaceAll("\\s+", " ").trim();
        
        return title;
    }
    
    /**
     * 截断超长标题
     */
    private static String truncateTitle(String title, int maxLength) {
        if (title == null || title.length() <= maxLength) {
            return title;
        }
        
        // 截断并添加省略号前缀
        return "..." + title.substring(title.length() - maxLength + 3);
    }
    
    /**
     * 从原始请求字符串提取标题并返回匹配信息（用于测试对话框）
     *
     * @param rawRequest 原始请求字符串
     * @param rules      规则列表
     * @param fallback   全局回退标题
     * @param maxLength  标题最大长度
     * @return 提取结果信息
     */
    public static ExtractionResult extractWithInfo(String rawRequest, List<TitleRule> rules,
                                                    String fallback, int maxLength) {
        if (rawRequest == null || rawRequest.trim().isEmpty()) {
            return new ExtractionResult(fallback != null ? fallback : "SQLMap", null, null);
        }
        
        if (rules == null || rules.isEmpty()) {
            String title = extractFromRawRequestByRule(rawRequest, TitleRule.createDefaultRule(), maxLength);
            return new ExtractionResult(title, "默认规则", TitleSourceType.URL_PATH);
        }
        
        // 按优先级排序启用的规则
        List<TitleRule> sortedEnabledRules = rules.stream()
            .filter(TitleRule::isEnabled)
            .sorted(Comparator.comparingInt(TitleRule::getPriority))
            .toList();
        
        // 依次尝试每个规则
        for (TitleRule rule : sortedEnabledRules) {
            try {
                String title = extractFromRawRequestByRule(rawRequest, rule, maxLength);
                if (title != null && !title.trim().isEmpty()) {
                    return new ExtractionResult(title, rule.getName(), rule.getSourceType());
                }
            } catch (Exception e) {
                LOGGER.debug("规则 '{}' 提取失败: {}", rule.getName(), e.getMessage());
            }
        }
        
        // 所有规则都失败，使用全局 fallback
        return new ExtractionResult(sanitizeAndTruncate(fallback != null ? fallback : "SQLMap", maxLength), null, null);
    }
    
    /**
     * 从原始请求字符串使用单个规则提取
     */
    private static String extractFromRawRequestByRule(String rawRequest, TitleRule rule, int maxLength) {
        if (rawRequest == null || rule == null) {
            return null;
        }
        
        String title = null;
        
        try {
            switch (rule.getSourceType()) {
                case URL_PATH:
                    title = extractUrlPathFromRawRequest(rawRequest);
                    break;
                case URL_PATH_SUB:
                    String path = extractUrlPathFromRawRequest(rawRequest);
                    title = extractSubstringByRule(path, rule);
                    break;
                case FIXED:
                    title = rule.getFixedValue();
                    break;
                case REGEX:
                    title = extractFromRegexRawByRule(rawRequest, rule);
                    break;
                case JSON_PATH:
                    String body = extractBodyFromRawRequest(rawRequest);
                    title = extractJsonPathValue(body, rule.getJsonPath());
                    break;
                case XPATH:
                    String xmlBody = extractBodyFromRawRequest(rawRequest);
                    title = extractXPathValue(xmlBody, rule.getXpath());
                    break;
                case FORM_FIELD:
                    String formBody = extractBodyFromRawRequest(rawRequest);
                    title = extractFormFieldValue(formBody, rule.getFormField());
                    break;
                default:
                    title = extractUrlPathFromRawRequest(rawRequest);
            }
        } catch (Exception e) {
            LOGGER.debug("规则 '{}' 提取异常: {}", rule.getName(), e.getMessage());
            title = null;
        }
        
        if (title == null || title.trim().isEmpty()) {
            return null;
        }
        
        return sanitizeAndTruncate(title, maxLength);
    }
    
    /**
     * 从字符串中提取子串（使用规则参数）
     */
    private static String extractSubstringByRule(String str, TitleRule rule) {
        if (str == null || str.isEmpty()) {
            return null;
        }
        
        // 移除开头的 /
        if (str.startsWith("/")) {
            str = str.substring(1);
        }
        
        try {
            int len = str.length();
            int start = parseIndex(rule.getPathSubStart(), len);
            int end = parseIndex(rule.getPathSubEnd(), len);
            
            start = Math.max(0, Math.min(start, len));
            end = Math.max(0, Math.min(end, len));
            
            if (start >= end) {
                return null;
            }
            
            return str.substring(start, end);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * 解析索引值
     */
    private static int parseIndex(String value, int length) {
        if (value == null || value.isEmpty()) {
            return 0;
        }
        
        try {
            int idx = Integer.parseInt(value.trim());
            if (idx < 0) {
                return length + idx;
            }
            return idx;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    /**
     * 使用正则表达式从原始请求字符串中提取（使用规则参数）
     */
    private static String extractFromRegexRawByRule(String rawRequest, TitleRule rule) {
        if (rule.getRegexPattern() == null || rule.getRegexPattern().isEmpty()) {
            return null;
        }
        
        String content = null;
        
        if (rule.getRegexSource() == RegexSource.URL) {
            content = extractUrlFromRawRequest(rawRequest);
        } else if (rule.getRegexSource() == RegexSource.REQUEST_BODY) {
            content = extractBodyFromRawRequest(rawRequest);
        } else {
            // FULL_REQUEST
            content = rawRequest;
        }
        
        if (content == null || content.isEmpty()) {
            return null;
        }
        
        return extractRegexValue(content, rule.getRegexPattern(), rule.getRegexGroup());
    }
}
