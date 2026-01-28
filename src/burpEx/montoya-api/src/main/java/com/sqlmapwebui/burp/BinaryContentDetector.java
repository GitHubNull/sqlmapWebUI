package com.sqlmapwebui.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.nio.charset.StandardCharsets;

/**
 * 二进制内容检测器
 * 
 * 用于检测HTTP请求是否包含二进制数据，仅允许纯文本请求发起扫描任务
 * 
 * 纯文本类型包括：
 * - text/* (text/plain, text/html, text/xml等)
 * - application/json
 * - application/xml, application/xhtml+xml
 * - application/x-www-form-urlencoded
 * - application/javascript
 * 
 * 二进制类型包括：
 * - application/octet-stream
 * - image/*, video/*, audio/*
 * - application/zip, application/pdf, application/gzip等
 * - multipart/form-data (可能包含文件上传)
 * 
 * @author SQLMap WebUI Team
 * @version 1.0.0
 */
public class BinaryContentDetector {
    
    // 纯文本Content-Type白名单（精确匹配）
    private static final Set<String> TEXT_CONTENT_TYPES = new HashSet<>(Arrays.asList(
        "application/json",
        "application/xml",
        "application/xhtml+xml",
        "application/x-www-form-urlencoded",
        "application/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "application/soap+xml",
        "application/rss+xml",
        "application/atom+xml",
        "application/xslt+xml",
        "application/mathml+xml",
        "application/x-ndjson",
        "application/ld+json",
        "application/vnd.api+json",
        "application/hal+json",
        "application/problem+json",
        "application/graphql"
    ));
    
    // 二进制Content-Type黑名单（精确匹配）
    private static final Set<String> BINARY_CONTENT_TYPES = new HashSet<>(Arrays.asList(
        "application/octet-stream",
        "application/zip",
        "application/x-zip-compressed",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
        "application/pdf",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/x-shockwave-flash",
        "application/java-archive",
        "application/x-executable",
        "application/x-dosexec",
        "application/x-msdos-program",
        "application/wasm"
    ));
    
    // 二进制Content-Type前缀黑名单
    private static final String[] BINARY_CONTENT_TYPE_PREFIXES = {
        "image/",
        "video/",
        "audio/",
        "font/",
        "model/"
    };
    
    // 检测结果
    public static class DetectionResult {
        private final boolean isBinary;
        private final String reason;
        
        public DetectionResult(boolean isBinary, String reason) {
            this.isBinary = isBinary;
            this.reason = reason;
        }
        
        public boolean isBinary() {
            return isBinary;
        }
        
        public String getReason() {
            return reason;
        }
        
        public boolean isTextContent() {
            return !isBinary;
        }
    }
    
    /**
     * 检测HTTP请求是否包含二进制内容
     * 
     * @param request HTTP请求对象
     * @return 检测结果
     */
    public static DetectionResult detect(HttpRequest request) {
        if (request == null) {
            return new DetectionResult(true, "请求对象为空");
        }
        
        // 1. 检查Content-Type
        String contentType = getContentType(request);
        if (contentType != null && !contentType.isEmpty()) {
            DetectionResult contentTypeResult = checkContentType(contentType);
            // 如果是已知文本类型，直接返回文本结果，不再进行后续检测
            if (!contentTypeResult.isBinary()) {
                return contentTypeResult;
            }
            // 如果是已知二进制类型，直接返回二进制结果
            if (contentTypeResult.getReason().startsWith("已知二进制类型")) {
                return contentTypeResult;
            }
        }
        
        // 2. 检查multipart/form-data（可能包含文件上传）
        if (isMultipartFormData(contentType)) {
            // 进一步检查是否真的包含文件上传
            byte[] body = request.body().getBytes();
            if (containsBinaryInMultipart(body)) {
                return new DetectionResult(true, "multipart/form-data包含二进制文件");
            }
        }
        
        // 3. 检查请求体是否包含二进制数据（仅针对未知类型）
        byte[] body = request.body().getBytes();
        if (body != null && body.length > 0) {
            DetectionResult bodyResult = checkBodyForBinary(body);
            if (bodyResult.isBinary()) {
                return bodyResult;
            }
        }
        
        return new DetectionResult(false, "纯文本内容");
    }
    
    /**
     * 获取Content-Type头
     */
    private static String getContentType(HttpRequest request) {
        for (HttpHeader header : request.headers()) {
            if ("Content-Type".equalsIgnoreCase(header.name())) {
                String value = header.value();
                // 去除charset等参数
                int semicolonIndex = value.indexOf(';');
                if (semicolonIndex > 0) {
                    value = value.substring(0, semicolonIndex);
                }
                return value.trim().toLowerCase();
            }
        }
        return null;
    }
    
    /**
     * 检查Content-Type是否为二进制类型
     */
    private static DetectionResult checkContentType(String contentType) {
        String lowerContentType = contentType.toLowerCase();
        
        // 检查是否为纯文本类型
        if (lowerContentType.startsWith("text/")) {
            return new DetectionResult(false, "text/*类型");
        }
        
        if (TEXT_CONTENT_TYPES.contains(lowerContentType)) {
            return new DetectionResult(false, "已知纯文本类型: " + contentType);
        }
        
        // 检查是否为二进制类型
        if (BINARY_CONTENT_TYPES.contains(lowerContentType)) {
            return new DetectionResult(true, "已知二进制类型: " + contentType);
        }
        
        // 检查二进制前缀
        for (String prefix : BINARY_CONTENT_TYPE_PREFIXES) {
            if (lowerContentType.startsWith(prefix)) {
                return new DetectionResult(true, "二进制类型前缀: " + prefix);
            }
        }
        
        // 未知类型，默认为纯文本
        return new DetectionResult(false, "未知类型，默认纯文本");
    }
    
    /**
     * 检查是否为multipart/form-data
     */
    private static boolean isMultipartFormData(String contentType) {
        return contentType != null && contentType.toLowerCase().startsWith("multipart/form-data");
    }
    
    /**
     * 检查multipart中是否包含二进制文件
     */
    private static boolean containsBinaryInMultipart(byte[] body) {
        if (body == null || body.length == 0) {
            return false;
        }
        
        try {
            // 使用UTF-8编码解析body，避免编码问题
            String bodyStr = new String(body, StandardCharsets.UTF_8);
            // 简单检查：如果包含Content-Type: image/、video/、audio/、application/octet-stream等
            String lowerBody = bodyStr.toLowerCase();
            return lowerBody.contains("content-type: image/") ||
                   lowerBody.contains("content-type: video/") ||
                   lowerBody.contains("content-type: audio/") ||
                   lowerBody.contains("content-type: application/octet-stream") ||
                   lowerBody.contains("content-type: application/pdf") ||
                   lowerBody.contains("content-type: application/zip");
        } catch (Exception e) {
            // 如果无法解析为字符串，可能包含二进制
            return true;
        }
    }
    
    /**
     * 检查请求体是否包含二进制数据
     * 
     * 使用多种启发式方法检测：
     * 1. 检查是否包含NULL字节
     * 2. 检查非可打印字符比例
     * 3. 检查常见二进制文件魔数（magic bytes）
     */
    private static DetectionResult checkBodyForBinary(byte[] body) {
        if (body == null || body.length == 0) {
            return new DetectionResult(false, "空请求体");
        }
        
        // 1. 检查常见二进制文件魔数
        if (hasBinaryMagicBytes(body)) {
            return new DetectionResult(true, "检测到二进制文件签名");
        }
        
        // 2. 检查NULL字节（二进制数据的强指标）
        for (byte b : body) {
            if (b == 0) {
                return new DetectionResult(true, "包含NULL字节");
            }
        }
        
        // 3. 检查非可打印字符比例
        int nonPrintableCount = 0;
        int checkLength = Math.min(body.length, 8192); // 只检查前8KB
        
        for (int i = 0; i < checkLength; i++) {
            byte b = body[i];
            // 可打印ASCII字符: 0x20-0x7E, 以及常见控制字符: TAB(0x09), LF(0x0A), CR(0x0D)
            if (!((b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D)) {
                // 检查是否为UTF-8多字节序列的一部分
                if ((b & 0x80) != 0) {
                    // 可能是UTF-8编码，继续计数但不直接判定为二进制
                    nonPrintableCount++;
                } else {
                    nonPrintableCount++;
                }
            }
        }
        
        // 如果非可打印字符超过10%，认为是二进制
        double ratio = (double) nonPrintableCount / checkLength;
        if (ratio > 0.10) {
            return new DetectionResult(true, String.format("非可打印字符比例过高: %.1f%%", ratio * 100));
        }
        
        return new DetectionResult(false, "纯文本内容");
    }
    
    /**
     * 检查常见二进制文件魔数
     */
    private static boolean hasBinaryMagicBytes(byte[] body) {
        if (body.length < 4) {
            return false;
        }
        
        // PNG: 89 50 4E 47
        if (body[0] == (byte) 0x89 && body[1] == 0x50 && body[2] == 0x4E && body[3] == 0x47) {
            return true;
        }
        
        // JPEG: FF D8 FF
        if (body[0] == (byte) 0xFF && body[1] == (byte) 0xD8 && body[2] == (byte) 0xFF) {
            return true;
        }
        
        // GIF: GIF8
        if (body[0] == 0x47 && body[1] == 0x49 && body[2] == 0x46 && body[3] == 0x38) {
            return true;
        }
        
        // PDF: %PDF
        if (body[0] == 0x25 && body[1] == 0x50 && body[2] == 0x44 && body[3] == 0x46) {
            return true;
        }
        
        // ZIP/DOCX/XLSX/PPTX: PK
        if (body[0] == 0x50 && body[1] == 0x4B && body[2] == 0x03 && body[3] == 0x04) {
            return true;
        }
        
        // RAR: Rar!
        if (body[0] == 0x52 && body[1] == 0x61 && body[2] == 0x72 && body[3] == 0x21) {
            return true;
        }
        
        // 7z: 7z magic
        if (body[0] == 0x37 && body[1] == 0x7A && body[2] == (byte) 0xBC && body[3] == (byte) 0xAF) {
            return true;
        }
        
        // EXE/DLL: MZ
        if (body[0] == 0x4D && body[1] == 0x5A) {
            return true;
        }
        
        // GZIP: 1F 8B
        if (body[0] == 0x1F && body[1] == (byte) 0x8B) {
            return true;
        }
        
        // WebP: RIFF....WEBP
        if (body.length >= 12 && body[0] == 0x52 && body[1] == 0x49 && body[2] == 0x46 && body[3] == 0x46) {
            if (body[8] == 0x57 && body[9] == 0x45 && body[10] == 0x42 && body[11] == 0x50) {
                return true;
            }
        }
        
        // BMP: BM
        if (body[0] == 0x42 && body[1] == 0x4D) {
            return true;
        }
        
        // WASM: \0asm
        if (body[0] == 0x00 && body[1] == 0x61 && body[2] == 0x73 && body[3] == 0x6D) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 便捷方法：直接判断请求是否为二进制
     */
    public static boolean isBinaryRequest(HttpRequest request) {
        return detect(request).isBinary();
    }
    
    /**
     * 便捷方法：直接判断请求是否为纯文本
     */
    public static boolean isTextRequest(HttpRequest request) {
        return detect(request).isTextContent();
    }
}
