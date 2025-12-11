package fingerprint

import "veo/pkg/utils/httpclient"

// FingerprintHTTPClient 指纹识别所需的 HTTP 客户端接口
// 组合了基础请求和带 Header 请求的能力，提供类型安全
type FingerprintHTTPClient interface {
	httpclient.HTTPClientInterface
	httpclient.HeaderAwareClient
}
