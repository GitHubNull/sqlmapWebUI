package com.sqlmapwebui.burp;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * HTTP请求去重器 (Legacy API版本)
 * 
 * 用于在批量发送扫描任务时自动过滤重复请求
 * 
 * 重复判断标准：
 * - 协议 (http/https)
 * - 请求方法 (GET/POST等)
 * - 主机
 * - 端口
 * - Path
 * - URL参数 (Query Parameters)
 * - Body参数
 * 
 * 以上所有条件都相同才认为是重复请求
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class RequestDeduplicator {
    
    /**
     * 去重结果类
     */
    public static class DedupeResult {
        private final List<IHttpRequestResponse> uniqueMessages;
        private final List<IHttpRequestResponse> duplicateMessages;
        
        public DedupeResult(List<IHttpRequestResponse> uniqueMessages, 
                           List<IHttpRequestResponse> duplicateMessages) {
            this.uniqueMessages = uniqueMessages;
            this.duplicateMessages = duplicateMessages;
        }
        
        public List<IHttpRequestResponse> getUniqueMessages() {
            return uniqueMessages;
        }
        
        public List<IHttpRequestResponse> getDuplicateMessages() {
            return duplicateMessages;
        }
        
        public int uniqueCount() {
            return uniqueMessages.size();
        }
        
        public int duplicateCount() {
            return duplicateMessages.size();
        }
        
        public int totalCount() {
            return uniqueMessages.size() + duplicateMessages.size();
        }
        
        public boolean hasDuplicates() {
            return !duplicateMessages.isEmpty();
        }
    }
    
    /**
     * 对请求列表进行去重
     * 
     * @param messages 原始请求数组
     * @param helpers Burp扩展帮助器
     * @return 去重结果
     */
    public static DedupeResult deduplicate(IHttpRequestResponse[] messages, IExtensionHelpers helpers) {
        return deduplicate(Arrays.asList(messages), helpers);
    }
    
    /**
     * 对请求列表进行去重
     * 
     * @param messages 原始请求列表
     * @param helpers Burp扩展帮助器
     * @return 去重结果
     */
    public static DedupeResult deduplicate(List<IHttpRequestResponse> messages, IExtensionHelpers helpers) {
        List<IHttpRequestResponse> uniqueMessages = new ArrayList<>();
        List<IHttpRequestResponse> duplicateMessages = new ArrayList<>();
        Set<String> seenFingerprints = new HashSet<>();
        
        for (IHttpRequestResponse message : messages) {
            String fingerprint = generateFingerprint(message, helpers);
            
            if (seenFingerprints.contains(fingerprint)) {
                duplicateMessages.add(message);
            } else {
                seenFingerprints.add(fingerprint);
                uniqueMessages.add(message);
            }
        }
        
        return new DedupeResult(uniqueMessages, duplicateMessages);
    }
    
    /**
     * 生成请求的唯一指纹
     * 
     * 指纹包含：协议、方法、主机、端口、路径、查询参数、请求体
     */
    public static String generateFingerprint(IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder sb = new StringBuilder();
        
        try {
            byte[] request = requestResponse.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            URL url = requestInfo.getUrl();
            
            // 1. 协议
            String protocol = url.getProtocol().toLowerCase();
            sb.append("protocol:").append(protocol).append("|");
            
            // 2. 请求方法
            String method = requestInfo.getMethod().toUpperCase();
            sb.append("method:").append(method).append("|");
            
            // 3. 主机
            String host = url.getHost().toLowerCase();
            sb.append("host:").append(host).append("|");
            
            // 4. 端口 (处理默认端口)
            int port = url.getPort();
            if (port == -1) {
                port = "https".equals(protocol) ? 443 : 80;
            }
            sb.append("port:").append(port).append("|");
            
            // 5. Path
            String path = url.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            sb.append("path:").append(path).append("|");
            
            // 6. 查询参数 (排序后比较，忽略顺序)
            String query = url.getQuery();
            String normalizedQuery = normalizeQueryParams(query);
            sb.append("query:").append(normalizedQuery).append("|");
            
            // 7. Body参数 (对于POST/PUT等)
            int bodyOffset = requestInfo.getBodyOffset();
            String body = "";
            if (bodyOffset < request.length) {
                body = new String(request, bodyOffset, request.length - bodyOffset, StandardCharsets.UTF_8);
            }
            String normalizedBody = normalizeBody(body, getContentType(requestInfo));
            sb.append("body:").append(normalizedBody);
            
        } catch (Exception e) {
            // 如果解析失败，使用原始请求的hash
            byte[] request = requestResponse.getRequest();
            sb.append("raw:").append(new String(request, StandardCharsets.UTF_8));
        }
        
        // 生成MD5哈希作为指纹
        return md5Hash(sb.toString());
    }
    
    /**
     * 规范化查询参数 (排序，忽略顺序差异)
     */
    private static String normalizeQueryParams(String query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        
        try {
            Map<String, List<String>> params = new TreeMap<>();
            String[] pairs = query.split("&");
            
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                String key = idx > 0 ? pair.substring(0, idx) : pair;
                String value = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : "";
                
                params.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
            }
            
            // 对每个key的values也排序
            StringBuilder result = new StringBuilder();
            for (Map.Entry<String, List<String>> entry : params.entrySet()) {
                Collections.sort(entry.getValue());
                for (String value : entry.getValue()) {
                    if (result.length() > 0) {
                        result.append("&");
                    }
                    result.append(entry.getKey()).append("=").append(value);
                }
            }
            
            return result.toString();
            
        } catch (Exception e) {
            return query;
        }
    }
    
    /**
     * 规范化请求体
     */
    private static String normalizeBody(String body, String contentType) {
        if (body == null || body.isEmpty()) {
            return "";
        }
        
        // 对于form-urlencoded，进行参数排序
        if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
            return normalizeQueryParams(body);
        }
        
        // 对于JSON，直接使用原始内容（或可以解析后规范化）
        // 这里简化处理，直接返回trim后的body
        return body.trim();
    }
    
    /**
     * 获取Content-Type
     */
    private static String getContentType(IRequestInfo requestInfo) {
        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring("content-type:".length()).trim().toLowerCase();
            }
        }
        return "";
    }
    
    /**
     * 生成MD5哈希
     */
    private static String md5Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // 降级方案：使用Java hashCode
            return String.valueOf(input.hashCode());
        }
    }
    
    /**
     * 获取请求的简短描述（用于日志）
     */
    public static String getRequestDescription(IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            URL url = requestInfo.getUrl();
            return requestInfo.getMethod() + " " + url.getHost() + url.getPath();
        } catch (Exception e) {
            return "Unknown Request";
        }
    }
}
