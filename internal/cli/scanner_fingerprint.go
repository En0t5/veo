package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/fingerprint"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)


func (sc *ScanController) runFingerprintModuleWithContext(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	// 模块启动提示
	// 模块开始前空行，提升可读性
	fmt.Println()
	if sc.fingerprintEngine != nil {
		summary := sc.fingerprintEngine.GetLoadedSummaryString()
		if summary != "" {
			logger.Infof("Start FingerPrint, Loaded FingerPrint Rules: %s", summary)
		} else {
			logger.Infof("Start FingerPrint")
		}
	} else {
		logger.Infof("Start FingerPrint")
	}
	logger.Debugf("开始指纹识别，数量: %d", len(targets))

	// 指纹识别需要解析最终跳转结果，因此临时放宽同主机限制
	if sc.requestProcessor != nil {
		originalRedirectScope := sc.requestProcessor.IsRedirectSameHostOnly()
		sc.requestProcessor.SetRedirectSameHostOnly(false)
		defer sc.requestProcessor.SetRedirectSameHostOnly(originalRedirectScope)
	}

	// 统一使用并发扫描逻辑 (DRY原则：消除重复的顺序扫描逻辑)
	// 即使只有一个目标，并发逻辑也能正确处理
	return sc.runConcurrentFingerprintWithContext(ctx, targets)
}

func (sc *ScanController) runFingerprintModule(targets []string) ([]interfaces.HTTPResponse, error) {
	return sc.runFingerprintModuleWithContext(context.Background(), targets)
}

func (sc *ScanController) runConcurrentFingerprintWithContext(parentCtx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("并发指纹识别模式，数量: %d", len(targets))

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	defer sc.requestProcessor.SetBatchMode(originalBatchMode)

	// 使用传入的 Context，如果被取消（如Ctrl+C），这里也会被取消
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex

	// 初始化实时结果保存
	var realtimeFile *os.File
	if sc.reportPath != "" {
		ext := filepath.Ext(sc.reportPath)
		base := strings.TrimSuffix(sc.reportPath, ext)
		realtimePath := base + "_realtime.csv"

		// [优化] 使用 O_APPEND 模式，如果文件存在则追加，不存在则创建
		// 如果是刚开始扫描，我们可能想覆盖？但考虑到断点续传或多次运行，O_APPEND 是安全的
		// 实际上，每次运行应该是一个新的会话，所以应该 truncate 还是 append？
		// 如果用户重启程序，通常希望是一个新的开始。
		// 但这里是在 runConcurrentFingerprint 中，如果它被多次调用呢？
		// ScanController 生命周期内，应该只初始化一次？
		// 实际上 runConcurrentFingerprint 是针对一次模块执行的。
		// 为了避免冲突，我们检查文件是否存在。

		// 简单策略：总是追加，但打印一个分割线或新的Header（如果文件为空）
		f, err := os.OpenFile(realtimePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			realtimeFile = f
			defer realtimeFile.Close()

			// 检查文件大小，如果为0则写入Header
			if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
				f.WriteString("URL,StatusCode,Title,Fingerprint\n")
			}
		} else {
			logger.Warnf("无法创建实时结果文件: %v", err)
		}
	}

	maxConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}
	logger.Debugf("指纹识别目标并发数设置为: %d", maxConcurrent)

	// 使用 Worker Pool 模式替代每个目标一个 Goroutine
	jobs := make(chan string, len(targets))
	resultsChan := make(chan []interfaces.HTTPResponse, len(targets))

	// 启动 Worker
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range jobs {
				// 检查全局上下文
				select {
				case <-ctx.Done():
					return
				default:
				}

				// 处理单个目标（使用较短的超时，避免单个卡死影响整体）
				// 单目标超时：完全使用全局超时配置
				taskTimeout := time.Duration(sc.timeoutSeconds) * time.Second
				if taskTimeout <= 0 {
					taskTimeout = 3 * time.Second // 防止为0的情况
				}
				targetCtx, targetCancel := context.WithTimeout(ctx, taskTimeout)
				results := sc.processSingleTargetFingerprintWithContext(targetCtx, targetURL)
				targetCancel()

				resultsChan <- results

				// 更新统计
				if sc.statsDisplay.IsEnabled() {
					sc.statsDisplay.IncrementCompletedHosts()
				}
			}
		}()
	}

	// 提交任务
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	// 结果收集协程
	done := make(chan struct{})
	go func() {
		for resList := range resultsChan {
			if len(resList) > 0 {
				resultsMu.Lock()
				allResults = append(allResults, resList...)
				resultsMu.Unlock()

				// 实时写入
				if realtimeFile != nil {
					for _, res := range resList {
						var fps []string
						for _, fp := range res.Fingerprints {
							fps = append(fps, fp.RuleName)
						}
						// 简单的CSV格式化
						line := fmt.Sprintf("\"%s\",\"%d\",\"%s\",\"%s\"\n",
							res.URL, res.StatusCode, strings.ReplaceAll(res.Title, "\"", "\"\""), strings.Join(fps, "|"))
						if _, err := realtimeFile.WriteString(line); err == nil {
							realtimeFile.Sync()
						}
					}
				}
			}
		}
		close(done)
	}()

	// 等待所有 Worker 完成
	wg.Wait()
	close(resultsChan)

	// 等待结果收集完成
	<-done

	// 主动探测 path 字段指纹
	pathResults := sc.performPathProbing(ctx, targets)
	if len(pathResults) > 0 {
		allResults = append(allResults, pathResults...)
		// 也可以追加到实时文件，但path探测通常较少
		if realtimeFile != nil {
			for _, res := range pathResults {
				var fps []string
				for _, fp := range res.Fingerprints {
					fps = append(fps, fp.RuleName)
				}
				line := fmt.Sprintf("\"%s\",\"%d\",\"%s\",\"%s\"\n",
					res.URL, res.StatusCode, strings.ReplaceAll(res.Title, "\"", "\"\""), strings.Join(fps, "|"))
				realtimeFile.WriteString(line)
				realtimeFile.Sync()
			}
		}
	}

	return allResults, nil
}

func (sc *ScanController) runConcurrentFingerprint(targets []string) ([]interfaces.HTTPResponse, error) {
	return sc.runConcurrentFingerprintWithContext(context.Background(), targets)
}

// processSingleTargetFingerprintWithContext 处理单个目标，支持传入 Context
func (sc *ScanController) processSingleTargetFingerprintWithContext(ctx context.Context, target string) []interfaces.HTTPResponse {
	// 使用channel接收结果以支持select超时
	resultChan := make(chan []interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("指纹识别panic: %v, 目标: %s", r, target)
				resultChan <- nil
			}
		}()

		resultChan <- sc.processSingleTargetFingerprint(target)
	}()

	select {
	case res := <-resultChan:
		return res
	case <-ctx.Done():
		logger.Debugf("目标处理超时: %s", target)
		return nil
	}
}

// processSingleTargetFingerprint 处理单个目标的指纹识别（多目标并发优化）
func (sc *ScanController) processSingleTargetFingerprint(target string) []interfaces.HTTPResponse {
	logger.Debugf("开始处理指纹识别: %s", target)

	// 为目标设置上下文
	targetDomain := extractDomainFromURL(target)
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext(fmt.Sprintf("finger-%s", targetDomain))
	defer sc.requestProcessor.SetModuleContext(originalContext)

	var results []interfaces.HTTPResponse

	responses := sc.requestProcessor.ProcessURLs([]string{target})

	for _, resp := range responses {
		fpResponse := sc.convertToFingerprintResponse(resp)
		if fpResponse == nil {
			logger.Debugf("响应转换失败: %s", resp.URL)
			continue
		}

		matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, sc.httpClient)

		httpResp := interfaces.HTTPResponse{
			URL:             resp.URL,
			StatusCode:      resp.StatusCode,
			ContentLength:   resp.ContentLength,
			ContentType:     resp.ContentType,
			ResponseHeaders: resp.ResponseHeaders,
			RequestHeaders:  resp.RequestHeaders,
			ResponseBody:    resp.ResponseBody,
			Title:           resp.Title,
			Server:          resp.Server,
			Duration:        resp.Duration,
			IsDirectory:     false,
		}
		if converted := convertFingerprintMatches(matches, true); len(converted) > 0 {
			httpResp.Fingerprints = converted
		}
		results = append(results, httpResp)

		logger.Debugf("%s 识别完成: %d", target, len(matches))
	}

	return results
}

// printFingerprintResultWithProgressClear 输出指纹结果并清除进度条（Helper function for DRY）
func (sc *ScanController) printFingerprintResultWithProgressClear(matches []*fingerprint.FingerprintMatch, response *fingerprint.HTTPResponse, formatter fingerprint.OutputFormatter, tag string) {
	if formatter != nil && len(matches) > 0 {
		// Clear progress bar line if needed
		if !sc.args.JSONOutput && sc.args.Stats {
			fmt.Printf("\r\033[K")
		}
		// Use original formatter
		formatter.FormatMatch(matches, response, tag)
	}
}

// performPathProbing 执行path字段主动探测（复用被动模式逻辑）
func (sc *ScanController) performPathProbing(ctx context.Context, targets []string) []interfaces.HTTPResponse {
	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		logger.Debug("指纹引擎未初始化，跳过path探测")
		return nil
	}

	// 检查Context是否取消
	select {
	case <-ctx.Done():
		logger.Warn("扫描已取消，跳过path探测阶段")
		return nil
	default:
	}

	// 检查是否有包含path字段的规则
	if !sc.fingerprintEngine.HasPathRules() {
		logger.Debug("没有包含path字段的规则，跳过path探测")
		return nil
	}

	var allResults []interfaces.HTTPResponse

	// 为每个目标执行path探测
	// [优化] 使用并发处理以提高批量扫描速度
	maxConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}

	// 1. 预处理：提取需要探测的唯一探测目标（Host根目录 或 包含子目录的完整BaseURL）
	// 避免将所有目标都扔进 Worker Pool，造成不必要的调度开销和"假死"现象
	uniqueTargets := sc.getUniqueProbeTargets(targets)

	if len(uniqueTargets) == 0 {
		logger.Debug("所有目标主机均已探测过或无需探测，跳过path探测阶段")
		return nil
	}

	if !sc.args.JSONOutput {
		logger.Infof("Start active path probing, total %d targets...", len(uniqueTargets))
	}

	outerConcurrent := maxConcurrent

	logger.Debugf("Active Path Probing Concurrency: %d", outerConcurrent)

	// 临时保存并替换 OutputFormatter 为 NullOutputFormatter，防止 Worker 自动打印日志干扰进度条
	// 我们将在收集到结果后手动打印（或者由 Engine 打印但我们控制时机）
	originalFormatter := sc.fingerprintEngine.GetOutputFormatter()
	// 使用 NullFormatter 暂时静默 Engine 的输出，我们将在 Worker 中手动控制输出
	sc.fingerprintEngine.SetOutputFormatter(fingerprint.NewNullOutputFormatter())
	defer sc.fingerprintEngine.SetOutputFormatter(originalFormatter) // 恢复

	// 使用 Worker Pool 模式
	jobs := make(chan string, len(uniqueTargets))
	resultsChan := make(chan []interfaces.HTTPResponse, len(uniqueTargets))

	var wg sync.WaitGroup

	// 进度显示
	var processedCount int32
	totalCount := int32(len(uniqueTargets))

	for i := 0; i < outerConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for baseURL := range jobs {
				// 检查Context取消
				select {
				case <-ctx.Done():
					return
				default:
				}

				var localResults []interfaces.HTTPResponse
				probeKey := baseURL // 使用 URL 本身作为去重键

				// 检查是否已经探测过此URL（避免重复探测）
				if sc.shouldTriggerPathProbing(probeKey) {
					logger.Debugf("触发path字段主动探测: %s", probeKey)
					sc.markHostAsProbed(probeKey)

					// 使用Context控制超时
					// 策略：完全使用全局超时配置
					probeTimeout := time.Duration(sc.timeoutSeconds) * time.Second
					if probeTimeout <= 0 {
						probeTimeout = 3 * time.Second // 防止为0的情况
					}
					// 继承传入的 ctx，这样父context取消时子context也会取消
					probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)

					// 调用指纹引擎的主动探测方法
					results, err := sc.fingerprintEngine.ExecuteActiveProbing(probeCtx, baseURL, sc.httpClient)
					cancel()

					if err != nil {
						logger.Debugf("Active probing error: %v", err)
					}

				if len(results) > 0 {
					logger.Debugf("Active probing found %d results for %s", len(results), baseURL)

					// 使用 Helper 输出结果
					if originalFormatter != nil {
						for _, res := range results {
							sc.printFingerprintResultWithProgressClear(res.Matches, res.Response, originalFormatter, "主动探测")
						}
					}

					for _, res := range results {
						httpResp := sc.convertProbeResult(res)
						localResults = append(localResults, httpResp)
					}
				}

				// [新增] 404页面指纹识别
				if res404 := sc.perform404PageProbing(baseURL, originalFormatter); res404 != nil {
					localResults = append(localResults, *res404)
				}
				} else {
					logger.Debugf("目标已探测过，跳过path探测: %s", probeKey)
				}
				resultsChan <- localResults

				// 更新进度
				curr := atomic.AddInt32(&processedCount, 1)
				if !sc.args.JSONOutput && sc.args.Stats && curr%2 == 0 {
					fmt.Printf("\rDeep Probing: %d/%d (%.1f%%)", curr, totalCount, float64(curr)/float64(totalCount)*100)
				}
			}
		}()
	}

	// 提交任务
	for _, baseURL := range uniqueTargets {
		jobs <- baseURL
	}
	close(jobs)

	// 收集结果协程
	resDone := make(chan struct{})
	go func() {
		for res := range resultsChan {
			if len(res) > 0 {
				allResults = append(allResults, res...)
			}
		}
		close(resDone)
	}()

	wg.Wait()
	if !sc.args.JSONOutput && sc.args.Stats {
		fmt.Println() // Newline after progress
	}
	close(resultsChan)
	<-resDone

	return allResults
}

// perform404PageProbing 执行404页面指纹识别
func (sc *ScanController) perform404PageProbing(baseURL string, formatter fingerprint.OutputFormatter) *interfaces.HTTPResponse {
	if sc.fingerprintEngine == nil {
		return nil
	}

	// 策略：完全使用全局超时配置
	probeTimeout := time.Duration(sc.timeoutSeconds) * time.Second
	if probeTimeout <= 0 {
		probeTimeout = 3 * time.Second // 防止为0的情况
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	result, err := sc.fingerprintEngine.Execute404Probing(ctx, baseURL, sc.httpClient)
	if err != nil {
		logger.Debugf("404 probing error: %v", err)
		return nil
	}
	
	if result != nil {
		// 使用 Helper 输出结果
		sc.printFingerprintResultWithProgressClear(result.Matches, result.Response, formatter, "404探测")

		httpResp := sc.convertProbeResult(result)
		return &httpResp
	}
	
	return nil
}

func (sc *ScanController) convertProbeResult(result *fingerprint.ProbeResult) interfaces.HTTPResponse {
	resp := result.Response
	httpResp := interfaces.HTTPResponse{
		URL:           resp.URL,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentType:   resp.ContentType,
		ResponseBody:  resp.Body,
		Title:         resp.Title,
		IsDirectory:   false,
	}
	if len(result.Matches) > 0 {
		httpResp.Fingerprints = convertFingerprintMatches(result.Matches, true)
	}
	return httpResp
}

func extractDomainFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	if len(rawURL) > 30 {
		return rawURL[:27] + "..."
	}
	return rawURL
}

// shouldTriggerPathProbing 检查是否应该触发path探测
func (sc *ScanController) shouldTriggerPathProbing(hostKey string) bool {
	sc.probedMutex.RLock()
	defer sc.probedMutex.RUnlock()

	// 检查是否已经探测过此主机
	return !sc.probedHosts[hostKey]
}

// getUniqueProbeTargets 提取唯一探测目标（Helper method）
func (sc *ScanController) getUniqueProbeTargets(targets []string) map[string]string {
	uniqueTargets := make(map[string]string)
	for _, t := range targets {
		// 策略：对于每个目标，我们总是尝试探测其根目录
		rootURL := sc.extractBaseURL(t)
		if sc.shouldTriggerPathProbing(rootURL) {
			uniqueTargets[rootURL] = rootURL
		}

		// 如果目标包含路径（且不等于根目录），我们也探测该路径
		fullURL := sc.extractBaseURLWithPath(t)
		// 简单比较：移除末尾斜杠后再比较，避免 http://x/ 和 http://x 视为不同
		if strings.TrimRight(fullURL, "/") != strings.TrimRight(rootURL, "/") {
			if sc.shouldTriggerPathProbing(fullURL) {
				uniqueTargets[fullURL] = fullURL
			}
		}
	}
	return uniqueTargets
}

// markHostAsProbed 标记主机为已探测
func (sc *ScanController) markHostAsProbed(hostKey string) {
	sc.probedMutex.Lock()
	defer sc.probedMutex.Unlock()
	sc.probedHosts[hostKey] = true
}
