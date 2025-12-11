package fingerprint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/redirect"
	"veo/pkg/utils/shared"
)

// ProbeResult 用于收集主动探测的匹配结果和响应对象
type ProbeResult struct {
	Response *HTTPResponse
	Matches  []*FingerprintMatch
}


// 引擎实现

// NewEngine 创建新的指纹识别引擎
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = getDefaultConfig()
	}

	engine := &Engine{
		config:      config,
		ruleManager: NewRuleManager(), // 初始化规则管理器
		matches:     make([]*FingerprintMatch, 0),
		dslParser:   NewDSLParser(),
		iconCache: NewIconCache(), // 使用组件初始化
		stats: &Statistics{
			StartTime: time.Now(),
		},
		staticExtensions:         append([]string(nil), StaticFileExtensions...),
		staticContentTypes:       append([]string(nil), StaticContentTypes...),
		staticFileFilterEnabled:  true,
		contentTypeFilterEnabled: true,
		showSnippet:              true, // 默认启用snippet捕获
		outputFormatter:          nil,  // 默认不输出,由外部注入
	}

	return engine
}


// SetStaticContentTypes 设置自定义静态Content-Type列表
func (e *Engine) SetStaticContentTypes(contentTypes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if contentTypes == nil {
		e.staticContentTypes = append([]string(nil), StaticContentTypes...)
	} else {
		e.staticContentTypes = cloneStringSlice(contentTypes)
	}
}

// SetStaticFileExtensions 设置自定义静态文件扩展名列表
func (e *Engine) SetStaticFileExtensions(extensions []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if extensions == nil {
		e.staticExtensions = append([]string(nil), StaticFileExtensions...)
	} else {
		e.staticExtensions = cloneStringSlice(extensions)
	}
}

// EnableSnippet 控制是否捕获指纹匹配片段(用于报告)
func (e *Engine) EnableSnippet(enabled bool) {
	e.mu.Lock()
	e.showSnippet = enabled
	e.mu.Unlock()
}

// EnableRuleLogging 控制是否输出匹配规则内容(已废弃,由OutputFormatter控制)
// 保留此方法以保持向后兼容
func (e *Engine) EnableRuleLogging(enabled bool) {
	e.mu.Lock()
	if formatter, ok := e.outputFormatter.(*ConsoleOutputFormatter); ok {
		formatter.SetShowRules(enabled)
	}
	e.mu.Unlock()
}

// EnableConsoleSnippet 控制是否在控制台输出指纹匹配片段(已废弃,由OutputFormatter控制)
// 保留此方法以保持向后兼容
func (e *Engine) EnableConsoleSnippet(enabled bool) {
	e.mu.Lock()
	if formatter, ok := e.outputFormatter.(*ConsoleOutputFormatter); ok {
		formatter.SetConsoleSnippetEnabled(enabled)
	}
	e.mu.Unlock()
}

// IsSnippetEnabled 返回是否启用指纹匹配片段捕获
func (e *Engine) IsSnippetEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.showSnippet
}

// SetOutputFormatter 设置输出格式化器
func (e *Engine) SetOutputFormatter(formatter OutputFormatter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.outputFormatter = formatter
}

// GetOutputFormatter 获取输出格式化器
func (e *Engine) GetOutputFormatter() OutputFormatter {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.outputFormatter
}

// SetStaticFileFilterEnabled 控制是否启用静态文件过滤
func (e *Engine) SetStaticFileFilterEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.staticFileFilterEnabled = enabled
}

// SetContentTypeFilterEnabled 控制是否启用Content-Type过滤
func (e *Engine) SetContentTypeFilterEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.contentTypeFilterEnabled = enabled
}

// LoadRules 加载指纹识别规则（支持单文件或目录）
func (e *Engine) LoadRules(rulesPath string) error {
	return e.ruleManager.LoadRules(rulesPath)
}

// GetLoadedSummaryString 返回已加载规则文件的摘要字符串
func (e *Engine) GetLoadedSummaryString() string {
	return e.ruleManager.GetLoadedSummaryString()
}

// AnalyzeResponse 分析响应包并进行指纹识别（基础版本，用于向后兼容）
func (e *Engine) AnalyzeResponse(response *HTTPResponse) []*FingerprintMatch {
	return e.AnalyzeResponseWithClient(response, nil)
}

// AnalyzeResponseWithClient 分析响应包并进行指纹识别（增强版，支持icon()函数主动探测）
func (e *Engine) AnalyzeResponseWithClient(response *HTTPResponse, httpClient httpclient.HTTPClientInterface) []*FingerprintMatch {
	// 检查是否应该过滤此响应
	if e.config.EnableFiltering && e.shouldFilterResponse(response) {
		atomic.AddInt64(&e.stats.FilteredRequests, 1)
		return nil
	}

	// 更新统计
	atomic.AddInt64(&e.stats.TotalRequests, 1)

	// 性能优化：移除信号量控制，统一在RequestProcessor层管理并发
	// 指纹匹配本身是CPU密集型操作，不需要额外的并发限制
	// HTTP请求的并发控制已在RequestProcessor层实现

	// 创建DSL上下文（支持主动探测）
	var ctx *DSLContext
	if httpClient != nil {
		// 从响应URL中提取基础URL
		baseURL := ""
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
		ctx = e.createDSLContextWithClient(response, httpClient, baseURL)
		logger.Debugf("创建增强DSL上下文，支持icon()主动探测: %s (HTTPClient: %v)", baseURL, httpClient != nil)
	} else {
		ctx = e.createDSLContext(response)
		logger.Debugf("创建基础DSL上下文，不支持icon()主动探测")
	}

	var matches []*FingerprintMatch

	// 遍历所有规则进行匹配
	// 性能优化：使用预计算的规则快照
	rules := e.ruleManager.GetRulesSnapshot()

	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
		}
	}

	// 更新匹配统计
	if len(matches) > 0 {
		atomic.AddInt64(&e.stats.MatchedRequests, 1)
		e.mu.Lock()
		e.stats.LastMatchTime = time.Now()
		e.matches = append(e.matches, matches...)
		e.mu.Unlock()
	}

	// 使用OutputFormatter输出结果
	if e.outputFormatter != nil {
		if len(matches) > 0 {
			e.outputFormatter.FormatMatch(matches, response)
		} else {
			e.outputFormatter.FormatNoMatch(response)
		}
	}

	if fetcher, ok := httpClient.(redirect.HTTPFetcher); ok {
		if redirected, err := redirect.FollowClientRedirect(response, fetcher); err == nil && redirected != nil {
			rMatches := e.AnalyzeResponseWithClientSilent(redirected, httpClient)
			if len(rMatches) > 0 {
				// 使用OutputFormatter输出重定向结果
				if e.outputFormatter != nil {
					e.outputFormatter.FormatMatch(rMatches, redirected)
				}
				matches = append(matches, rMatches...)
			}
		} else if err != nil {
			logger.Debugf("客户端重定向抓取失败: %v", err)
		}
	}

	return matches
}


// AnalyzeResponseWithClientSilent 分析响应包并进行指纹识别（静默版本，不自动输出结果）
// 专用于404页面等需要自定义输出格式的场景
func (e *Engine) AnalyzeResponseWithClientSilent(response *HTTPResponse, httpClient interface{}) []*FingerprintMatch {
	// 类型适配：尝试转换为 HTTPClientInterface
	var client httpclient.HTTPClientInterface
	if httpClient != nil {
		if c, ok := httpClient.(httpclient.HTTPClientInterface); ok {
			client = c
		}
	}

	// 检查是否应该过滤此响应
	if e.config.EnableFiltering && e.shouldFilterResponse(response) {
		atomic.AddInt64(&e.stats.FilteredRequests, 1)
		return nil
	}

	// 更新统计
	atomic.AddInt64(&e.stats.TotalRequests, 1)

	// 创建DSL上下文（支持主动探测）
	var ctx *DSLContext
	if client != nil {
		// 从响应URL中提取基础URL
		baseURL := ""
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
		ctx = e.createDSLContextWithClient(response, client, baseURL)
		logger.Debugf("创建增强DSL上下文（静默模式），支持icon()主动探测: %s (HTTPClient: %v)", baseURL, client != nil)
	} else {
		ctx = e.createDSLContext(response)
		logger.Debugf("创建基础DSL上下文（静默模式），不支持icon()主动探测")
	}

	var matches []*FingerprintMatch

	// 遍历所有规则进行匹配
	// 性能优化：使用预计算的规则快照
	rules := e.ruleManager.GetRulesSnapshot()

	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
		}
	}

	// 更新匹配统计但不输出日志（静默模式）
	if len(matches) > 0 {
		atomic.AddInt64(&e.stats.MatchedRequests, 1)
		e.mu.Lock()
		e.stats.LastMatchTime = time.Now()
		e.matches = append(e.matches, matches...)
		e.mu.Unlock()

		// [关键] 静默模式：不调用 outputFingerprintMatches，由调用方负责输出
		logger.Debugf("静默模式匹配完成，匹配数量: %d，跳过自动输出", len(matches))
	}

	return matches
}

// matchRule 匹配单个规则
func (e *Engine) matchRule(rule *FingerprintRule, ctx *DSLContext) *FingerprintMatch {
	// 如果没有DSL表达式，直接返回nil
	if len(rule.DSL) == 0 {
		return nil
	}

	// 获取条件类型，默认为"or"
	condition := strings.ToLower(strings.TrimSpace(rule.Condition))
	if condition == "" {
		condition = "or"
	}

	matchedDSLs := make([]string, 0)

	// 根据条件类型执行匹配
	switch condition {
	case "and":
		// AND条件：所有DSL表达式都必须匹配
		for _, dsl := range rule.DSL {
			if e.dslParser.EvaluateDSL(dsl, ctx) {
				matchedDSLs = append(matchedDSLs, dsl)
			} else {
				// 有一个不匹配就返回nil
				return nil
			}
		}
		// 所有表达式都匹配成功
		if len(matchedDSLs) == len(rule.DSL) {
			snippet := ""
			if e.shouldCaptureSnippet(rule) {
				for _, dsl := range matchedDSLs {
					snippet = e.extractSnippetForDSL(dsl, ctx)
					if snippet != "" {
						break
					}
				}
			}
			return &FingerprintMatch{
				URL:        ctx.URL,
				RuleName:   rule.Name,
				Technology: rule.Name,
				DSLMatched: fmt.Sprintf("AND(%s)", strings.Join(matchedDSLs, " && ")),
				Timestamp:  time.Now(),
				Snippet:    snippet,
			}
		}
	case "or":
		fallthrough // OR和default使用相同逻辑
	default:
		if condition != "or" {
			logger.Warnf("不支持的条件类型: %s, 使用默认OR条件", condition)
		}
		// OR条件：任意一个DSL表达式匹配即可
		for _, dsl := range rule.DSL {
			if e.dslParser.EvaluateDSL(dsl, ctx) {
				snippet := ""
				if e.shouldCaptureSnippet(rule) {
					snippet = e.extractSnippetForDSL(dsl, ctx)
				}
				return &FingerprintMatch{
					URL:        ctx.URL,
					RuleName:   rule.Name,
					Technology: rule.Name,
					DSLMatched: dsl,
					Timestamp:  time.Now(),
					Snippet:    snippet,
				}
			}
		}
	}

	return nil
}

func (e *Engine) shouldCaptureSnippet(rule *FingerprintRule) bool {
	if rule == nil {
		return false
	}
	return e.IsSnippetEnabled()
}

func (e *Engine) extractSnippetForDSL(dsl string, ctx *DSLContext) string {
	if ctx == nil || strings.TrimSpace(dsl) == "" {
		return ""
	}
	snippet := e.dslParser.ExtractSnippet(dsl, ctx)
	return snippet
}

// createDSLContext 创建DSL解析上下文（基础版本，用于被动识别）
func (e *Engine) createDSLContext(response *HTTPResponse) *DSLContext {
	return e.createDSLContextWithClient(response, nil, "")
}

// createDSLContextWithClient 创建DSL解析上下文（增强版，支持主动探测）
func (e *Engine) createDSLContextWithClient(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, baseURL string) *DSLContext {
	headers := make(map[string][]string)
	if response != nil && len(response.ResponseHeaders) > 0 {
		headers = make(map[string][]string, len(response.ResponseHeaders))
		for name, values := range response.ResponseHeaders {
			if len(values) == 0 {
				continue
			}
			dup := make([]string, len(values))
			copy(dup, values)
			headers[name] = dup
		}
	}

	if baseURL == "" && response != nil && response.URL != "" {
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
	}

	var body, urlStr, method string
	if response != nil {
		body = response.Body
		urlStr = response.URL
		method = response.Method
	}

	return &DSLContext{
		Response:   response,
		Headers:    headers,
		Body:       body,
		URL:        urlStr,
		Method:     method,
		HTTPClient: httpClient,
		BaseURL:    baseURL,
		Engine:     e,
	}
}

// shouldFilterResponse 检查是否应该过滤响应
func (e *Engine) shouldFilterResponse(response *HTTPResponse) bool {
	// 检查响应体大小
	if e.config.MaxBodySize > 0 && len(response.Body) > e.config.MaxBodySize {
		logger.Debugf("过滤大响应体: %s (大小: %d bytes, 限制: %d bytes)",
			response.URL, len(response.Body), e.config.MaxBodySize)
		return true
	}

	// 检查是否为静态文件（基于URL路径）
	if e.isStaticFile(response.URL) {
		logger.Debugf("过滤静态文件: %s", response.URL)
		return true
	}

	// 检查Content-Type
	if e.isStaticContentType(response.ContentType) {
		logger.Debugf("过滤静态内容类型: %s (Content-Type: %s)",
			response.URL, response.ContentType)
		return true
	}

	return false
}

// isStaticFile 检查URL是否指向静态文件（使用共享工具）
func (e *Engine) isStaticFile(rawURL string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.staticFileFilterEnabled || len(e.staticExtensions) == 0 {
		return false
	}

	lowerURL := strings.ToLower(rawURL)
	for _, ext := range e.staticExtensions {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(lowerURL, strings.ToLower(ext)) {
			return true
		}
	}

	return false
}

// isStaticContentType 检查Content-Type是否为静态类型
func (e *Engine) isStaticContentType(contentType string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.contentTypeFilterEnabled || len(e.staticContentTypes) == 0 {
		return false
	}

	contentType = strings.ToLower(contentType)

	for _, staticType := range e.staticContentTypes {
		if staticType == "" {
			continue
		}
		if strings.HasPrefix(contentType, strings.ToLower(staticType)) {
			return true
		}
	}

	return false
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

// GetMatches 获取所有匹配结果
func (e *Engine) GetMatches() []*FingerprintMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 返回副本避免并发修改
	matches := make([]*FingerprintMatch, len(e.matches))
	copy(matches, e.matches)
	return matches
}

// GetStats 获取统计信息
func (e *Engine) GetStats() *Statistics {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 返回副本
	stats := &Statistics{
		TotalRequests:    atomic.LoadInt64(&e.stats.TotalRequests),
		MatchedRequests:  atomic.LoadInt64(&e.stats.MatchedRequests),
		FilteredRequests: atomic.LoadInt64(&e.stats.FilteredRequests),
		RulesLoaded:      e.stats.RulesLoaded,
		StartTime:        e.stats.StartTime,
		LastMatchTime:    e.stats.LastMatchTime,
	}

	return stats
}

// GetRulesCount 获取加载的规则数量
func (e *Engine) GetRulesCount() int {
	return e.ruleManager.GetRulesCount()
}

// 配置和辅助方法

// getDefaultConfig 获取默认配置
func getDefaultConfig() *EngineConfig {
	maxConcurrency := 20 // 默认最小并发数

	return &EngineConfig{
		RulesPath:       "config/fingerprint/", // [修改] 改为目录路径，自动加载所有YAML文件
		MaxConcurrency:  maxConcurrency,
		EnableFiltering: true,
		MaxBodySize:     1024 * 1024, // 1MB
		LogMatches:      true,
	}
}

// 缓存和去重相关方法

// getIconHash 获取图标哈希值（委托给IconCache组件）
func (e *Engine) getIconHash(iconURL string, httpClient httpclient.HTTPClientInterface) (string, error) {
	return e.iconCache.GetHash(iconURL, httpClient)
}

// 主动探测相关方法

// TriggerActiveProbing 触发主动探测（异步，用于被动模式）
func (e *Engine) TriggerActiveProbing(baseURL string, httpClient httpclient.HTTPClientInterface) {
	if httpClient == nil {
		return
	}
	go func() {
		// 使用默认超时
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		// 执行主动Path探测
		_, _ = e.ExecuteActiveProbing(ctx, baseURL, httpClient)
		
		// 执行404探测
		ctx404, cancel404 := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel404()
		_, _ = e.Execute404Probing(ctx404, baseURL, httpClient)
	}()
}

// ExecuteActiveProbing 执行主动指纹探测（同步返回结果）
func (e *Engine) ExecuteActiveProbing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) ([]*ProbeResult, error) {
	logger.Debugf("开始主动探测: %s", baseURL)

	// 获取所有包含path字段的规则和header规则
	// 性能优化：直接从 RuleManager 获取，无需遍历
	pathRules := e.ruleManager.GetPathRules()
	headerOnlyRules := e.ruleManager.GetHeaderRules()
	totalPaths := e.ruleManager.GetPathRulesCount()

	if totalPaths == 0 && len(headerOnlyRules) == 0 {
		logger.Debug("没有需要主动探测的规则，跳过主动探测")
		return nil, nil
	}

	// 解析baseURL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("URL解析失败: %v", err)
	}
	scheme := parsedURL.Scheme
	host := parsedURL.Host

	var results []*ProbeResult
	var resultsMu sync.Mutex

	// 任务列表
	type task struct {
		rule *FingerprintRule
		path string
	}
	var tasks []task

	for _, rule := range pathRules {
		for _, p := range rule.Paths {
			tasks = append(tasks, task{rule: rule, path: strings.TrimSpace(p)})
		}
	}
	// Header规则作为根路径任务添加（简化处理）
	for _, rule := range headerOnlyRules {
		tasks = append(tasks, task{rule: rule, path: "/"})
	}

	// 并发控制
	concurrency := e.config.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 20
	}

	// 任务通道
	taskChan := make(chan task, len(tasks))
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)

	var wg sync.WaitGroup

	// 启动固定数量的工作协程
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case tk, ok := <-taskChan:
					if !ok {
						return
					}
					
					probeURL := buildProbeURLFromParts(scheme, host, tk.path)
					
					// 构造Headers
					var headers map[string]string
					if tk.rule.HasHeaders() {
						headers = tk.rule.GetHeaderMap()
					}

					// 发起请求
					body, statusCode, err := makeRequestWithOptionalHeaders(httpClient, probeURL, headers)
					if err != nil {
						continue
					}

					// 构造响应对象
					resp := &HTTPResponse{
						URL:             probeURL,
						Method:          "GET",
						StatusCode:      statusCode,
						ResponseHeaders: make(map[string][]string),
						Body:            body,
						ContentType:     "text/html",
						ContentLength:   int64(len(body)),
						Title:           shared.ExtractTitle(body),
					}

					// 匹配规则
					dslCtx := e.createDSLContextWithClient(resp, httpClient, baseURL)
					if match := e.matchRule(tk.rule, dslCtx); match != nil {
						// 使用OutputFormatter输出
						if e.outputFormatter != nil {
							e.outputFormatter.FormatMatch([]*FingerprintMatch{match}, resp, "主动探测")
						}
						
						resultsMu.Lock()
						results = append(results, &ProbeResult{
							Response: resp,
							Matches:  []*FingerprintMatch{match},
						})
						resultsMu.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// Execute404Probing 执行404页面探测（同步返回结果）
func (e *Engine) Execute404Probing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) (*ProbeResult, error) {
	logger.Debugf("开始404页面指纹识别: %s", baseURL)

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("URL解析失败: %v", err)
	}
	scheme := parsedURL.Scheme
	host := parsedURL.Host
	notFoundURL := fmt.Sprintf("%s://%s/404test", scheme, host)

	// 发起请求
	body, statusCode, err := makeRequestWithOptionalHeaders(httpClient, notFoundURL, nil)
	if err != nil {
		return nil, err
	}

	resp := &HTTPResponse{
		URL:             notFoundURL,
		Method:          "GET",
		StatusCode:      statusCode,
		ResponseHeaders: make(map[string][]string),
		Body:            body,
		ContentType:     "text/html",
		ContentLength:   int64(len(body)),
		Title:           shared.ExtractTitle(body),
	}

	// 全量匹配
	matches := e.match404PageFingerprints(resp, httpClient, baseURL)
	if len(matches) > 0 {
		// 使用OutputFormatter输出
		if e.outputFormatter != nil {
			e.outputFormatter.FormatMatch(matches, resp, "404探测")
		}
		return &ProbeResult{
			Response: resp,
			Matches:  matches,
		}, nil
	}

	return nil, nil
}

// match404PageFingerprints 对404页面进行全量指纹规则匹配
func (e *Engine) match404PageFingerprints(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, baseURL string) []*FingerprintMatch {
	logger.Debugf("开始404页面全量指纹匹配")

	// 创建DSL上下文（支持主动探测）
	ctx := e.createDSLContextWithClient(response, httpClient, baseURL)

	var matches []*FingerprintMatch

	// 获取所有指纹规则进行匹配（使用快照）
	rules := e.ruleManager.GetRulesSnapshot()

	// 遍历所有规则进行匹配
	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
			logger.Debugf("404页面匹配到指纹: %s (规则: %s)",
				match.Technology, match.RuleName)
		}
	}

	logger.Debugf("404页面全量匹配完成，共匹配到 %d 个指纹", len(matches))
	return matches
}

func makeRequestWithOptionalHeaders(httpClient httpclient.HTTPClientInterface, targetURL string, headers map[string]string) (string, int, error) {
	if len(headers) > 0 {
		if headerClient, ok := httpClient.(httpclient.HeaderAwareClient); ok {
			return headerClient.MakeRequestWithHeaders(targetURL, headers)
		}
		logger.Debugf("HTTP客户端不支持自定义头部，使用默认请求: %s", targetURL)
	}

	return httpClient.MakeRequest(targetURL)
}

func buildProbeURLFromParts(scheme, host, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	trimmed := path
	if trimmed == "" {
		trimmed = "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, trimmed)
}

// HasPathRules 检查是否有包含path字段的规则
func (e *Engine) HasPathRules() bool {
	return e.ruleManager.HasPathRules()
}

// GetPathRulesCount 获取包含path字段的规则数量
func (e *Engine) GetPathRulesCount() int {
	return e.ruleManager.GetPathRulesCount()
}

// GetPathRules 获取所有包含path字段的规则（公共方法，供CLI使用）
func (e *Engine) GetPathRules() []*FingerprintRule {
	return e.ruleManager.GetPathRules()
}

// MatchSpecificRule 匹配指定的单个规则（公开方法，供CLI使用）
func (e *Engine) MatchSpecificRule(rule *FingerprintRule, response *HTTPResponse, httpClient httpclient.HTTPClientInterface, baseURL string) *FingerprintMatch {
	// 创建DSL上下文（支持主动探测）
	ctx := e.createDSLContextWithClient(response, httpClient, baseURL)
	// 匹配指定规则
	return e.matchRule(rule, ctx)
}
