# SQLMap `-r` 参数误识别 GET 请求为 POST 请求 —— GitHub Issue 报告

---

## Issue 标题

`-r` option incorrectly treats GET request as POST when request file contains trailing newlines

---

## 问题描述 / Description

When using SQLMap with the `-r` option to load an HTTP request from a file, if the request file contains **trailing newlines after the standard HTTP empty line** (i.e., more than one `\r\n` or `\n` at the end), SQLMap incorrectly interprets the request as a **POST request**, regardless of the actual HTTP method specified in the request line.

This behavior affects any HTTP method (GET, PUT, DELETE, etc.) when the request file is not strictly terminated after the single empty line that separates headers from the body.

A typical scenario where this bug is triggered: the original request is a POST (see "Original Request" below), but after editing it in Burp Repeater to change the method to GET and removing the body, the generated request file may still contain trailing newlines. SQLMap then incorrectly treats the edited GET request as POST.

---

## 复现步骤 / Steps to Reproduce

### Original Request (for context)

The original HTTP request before editing was a POST with a JSON body:

```http
POST /api/user/login HTTP/1.1
Host: 127.0.0.1:9527
Content-Length: 37
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
Content-Type: application/json
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:9527
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:9527/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"username":"test","password":"test"}
```

### Reproducible Request File

After editing the request in Burp Repeater (changing method to GET and removing the body), create a file `requests.txt` with the following content. Note that it ends with **two empty lines** instead of one:

```http
GET /api/user/login HTTP/1.1
Host: 127.0.0.1:9527
Content-Length: 0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
Content-Type: application/json
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:9527
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:9527/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive


```

> **Note:** The file ends with **two empty lines** instead of one. In other words, there are extra newline characters after the standard HTTP empty line.

Run SQLMap with the `-r` option:

```bash
python sqlmap.py -r requests.txt --batch --level=1 --risk=1
```

To verify the actual HTTP method sent by SQLMap, you can proxy the traffic through Burp Suite or any other intercepting proxy using the `--proxy` option:

```bash
python sqlmap.py -r requests.txt --batch --level=1 --risk=1 --proxy=http://127.0.0.1:8080
```

Observe that SQLMap treats this as a **POST request** and attempts to inject into the "body" parameters, even though the request method is explicitly `GET`.

---

## 预期行为 / Expected Behavior

SQLMap should respect the HTTP method specified in the request line (`GET` in this case) and should not incorrectly infer `POST` solely based on trailing newlines in the request file.

According to RFC 7230, the empty line (`CRLF CRLF`) marks the end of the header section. Any content **after** that empty line constitutes the message body. However, **trailing empty lines alone** (without actual body content) should not cause SQLMap to change the request method or assume the presence of a body.

---

## 实际行为 / Actual Behavior

SQLMap detects "content" after the first empty line (even if it's just additional newline characters) and proceeds to:
- Treat the request as a **POST request**
- Attempt to parse and inject into what it believes is the request body
- Ignore or mishandle URL/query parameters that should be the actual injection targets

---

## 环境信息 / Environment

- **SQLMap version:** 1.10 (also affects 1.9.11.3 and likely earlier versions)
- **Python version:** 3.10+
- **OS:** Windows 10 (also reproducible on Windows 11 and Linux)

---

## 根因分析 / Root Cause Analysis

The issue appears to be in how SQLMap parses the request file when the `-r` option is used. Specifically, the parser likely checks for the presence of **any bytes after the first `\r\n\r\n`** (or `\n\n`) sequence. If trailing newlines exist, the parser assumes there is a message body and consequently switches the request method to `POST`.

A more robust approach would be:
1. Strip trailing whitespace/newlines from the end of the request file **before** determining if a body exists.
2. Only treat the request as having a body if there is **non-whitespace content** after the header-empty-line.
3. Always preserve the HTTP method explicitly stated in the request line.

---

## 影响范围 / Impact

This bug affects automated workflows and third-party tools (e.g., Burp Suite extensions, custom scripts) that generate HTTP request files for SQLMap. It is common for text editors, logging tools, or programmatic file writers to append trailing newlines, making this issue easy to trigger unintentionally.

---

## 建议修复 / Suggested Fix

In the request file parsing logic (likely within `lib/request/connect.py` or similar), consider stripping trailing newlines before deciding whether a body is present:

```python
# Pseudo-code suggestion
raw_request = read_file(request_file)
# Split headers and body at the first empty line
header_part, _, body_part = raw_request.partition('\r\n\r\n')
# Strip trailing whitespace from the body before evaluation
body_part = body_part.rstrip('\r\n')
if not body_part:
    # No actual body content; preserve the original method
    has_body = False
else:
    has_body = True
```

Alternatively, ensure that the HTTP method from the request line is never overridden unless explicitly requested by the user (e.g., via `--method`).

---

## 附件 / Attachments

- `requests.txt` — Minimal reproducible request file (see "Steps to Reproduce" above)

---

## 备注 / Additional Notes

This issue was discovered while integrating SQLMap with the [SQLMap WebUI](https://github.com/c0ny1/sqlmap-webui) project, where HTTP request files are generated programmatically. Trailing newlines occasionally occur during file generation, leading to unexpected POST behavior on what should be GET-based scans.

Thank you for maintaining SQLMap!

---
