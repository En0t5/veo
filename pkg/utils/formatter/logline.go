package formatter

import (
	"net/url"
	"strings"
)

// FormatTitleForMatch 根据是否命中指纹选择标题颜色
func FormatTitleForMatch(title string, matched bool) string {
	if strings.TrimSpace(title) == "" {
		title = "无标题"
	}
	if matched {
		return FormatFingerprintTitle(title)
	}
	return FormatTitle(title)
}

// FormatLogLine 构造统一的日志输出格式：URL 状态码 标题 Content-Length Content-Type 指纹
func FormatLogLine(url string, statusCode int, title string, contentLength int64, contentType string, fingerprints []string, matched bool, tags ...string) string {
	if contentLength < 0 {
		contentLength = 0
	}

	parts := []string{
		FormatURL(url),
		FormatStatusCode(statusCode),
		FormatTitleForMatch(title, matched),
		FormatContentLength(int(contentLength)),
		FormatContentType(contentType),
	}

	fp := strings.TrimSpace(strings.Join(fingerprints, " "))
	if fp == "" {
		fp = "-"
	}
	parts = append(parts, fp)

	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		parts = append(parts, FormatFingerprintTag(tag))
	}

	return strings.Join(parts, " ")
}

// FormatLogLineWithURLSuffix 构造支持URL后缀的日志行（用于长URL单行展示）
func FormatLogLineWithURLSuffix(url string, urlSuffix string, statusCode int, title string, contentLength int64, contentType string, fingerprints []string, matched bool, tags ...string) string {
	if strings.TrimSpace(urlSuffix) == "" {
		return FormatLogLine(url, statusCode, title, contentLength, contentType, fingerprints, matched, tags...)
	}
	if contentLength < 0 {
		contentLength = 0
	}

	urlPart := formatURLWithSuffix(url, urlSuffix)

	parts := []string{
		urlPart,
		FormatStatusCode(statusCode),
		FormatTitleForMatch(title, matched),
		FormatContentLength(int(contentLength)),
		FormatContentType(contentType),
	}

	fp := strings.TrimSpace(strings.Join(fingerprints, " "))
	if fp == "" {
		fp = "-"
	}
	parts = append(parts, fp)

	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		parts = append(parts, FormatFingerprintTag(tag))
	}

	return strings.Join(parts, " ")
}

func formatURLWithSuffix(url string, suffix string) string {
	url = strings.TrimSpace(url)
	suffix = strings.TrimSpace(suffix)
	if suffix == "" {
		return FormatURL(url)
	}
	if !shouldUseColors() {
		return url + " " + suffix
	}
	return FormatFullURL(url) + " " + FormatFullURL(suffix)
}

// SplitURLForLog 当URL过长时拆分为基础URL与路径/查询，保证单行展示
func SplitURLForLog(rawURL string, limit int) (string, string) {
	if limit <= 0 || len(rawURL) <= limit {
		return rawURL, ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return rawURL, ""
	}

	detail := parsed.RequestURI()
	if parsed.Fragment != "" {
		detail += "#" + parsed.Fragment
	}
	if detail == "" || detail == "/" {
		return rawURL, ""
	}

	baseURL := parsed.Scheme + "://" + parsed.Host + "/"
	return baseURL, detail
}
