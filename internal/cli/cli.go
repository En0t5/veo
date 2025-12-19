package cli

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"veo/internal/core/config"
	"veo/pkg/core/console"
	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	fpaddon "veo/pkg/fingerprint"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
	"veo/pkg/utils/processor/auth"
	"veo/proxy"
)

// CLIApp CLI应用程序
type CLIApp struct {
	proxy             *proxy.Proxy
	collector         *dirscan.Collector
	consoleManager    *console.ConsoleManager
	dirscanModule     *dirscan.DirscanModule
	fingerprintAddon  *fpaddon.FingerprintAddon
	authLearningAddon *auth.AuthLearningAddon
	proxyStarted      bool
	args              *CLIArgs
}

var app *CLIApp

// Execute 执行CLI命令
func Execute() {
	// 优先初始化配置系统
	if err := config.InitConfig(); err != nil {
		// 如果配置加载失败，使用默认配置
		fmt.Printf("配置文件加载失败，使用默认配置: %v\n", err)
	}

	// 初始化日志系统
	loggerConfig := &logger.LogConfig{
		Level:       "info",
		ColorOutput: true,
	}
	if err := logger.InitializeLogger(loggerConfig); err != nil {
		// 如果初始化失败，使用默认配置
		logger.InitializeLogger(nil)
	}
	logger.Debug("日志系统初始化完成")

	// 初始化formatter包的Windows ANSI支持
	// Windows 10+默认支持ANSI颜色
	if runtime.GOOS == "windows" {
		formatter.SetWindowsANSISupported(true)
		logger.Debug("Windows ANSI颜色支持已启用")
	}

	// 解析命令行参数
	args := ParseCLIArgs()

	// 应用CLI参数到配置（包括--debug标志）
	applyArgsToConfig(args)

	// 处理指纹库更新逻辑 (前置处理，如果是更新操作则直接退出)
	handleRuleUpdates(args)

	//  提前显示启动信息，确保banner在所有日志输出之前显示
	displayStartupInfo(args)

	// 初始化应用程序
	var err error
	app, err = initializeApp(args)
	if err != nil {
		logger.Fatalf("初始化应用程序失败: %v", err)
	}

	// 根据模式启动应用程序
	if args.Listen {
		// 被动代理模式
		if err := startApplication(args); err != nil {
			logger.Fatalf("启动应用程序失败: %v", err)
		}
		// 等待中断信号或用户输入
		waitForSignal()
	} else {
		// 主动扫描模式
		if err := runActiveScanMode(args); err != nil {
			logger.Fatalf("主动扫描失败: %v", err)
		}
	}
}

// initializeReportGenerator 初始化报告生成器（已优化为无操作）
func initializeReportGenerator() {
	// 新架构中过滤器已经独立化，不再需要全局设置
	logger.Debug("报告生成器已独立化，无需全局设置")
}

// initializeApp 初始化应用程序
func initializeApp(args *CLIArgs) (*CLIApp, error) {
	// 配置系统和日志系统已在Execute()函数开始时初始化，这里无需重复

	// 初始化报告生成器
	initializeReportGenerator()

	// 创建代理服务器
	logger.Debug("创建代理服务器...")
	proxyServer, err := createProxy()
	if err != nil {
		return nil, fmt.Errorf("创建代理服务器失败: %v", err)
	}

	// 只在启用dirscan模块时创建collector和相关组件
	var collectorInstance *dirscan.Collector
	var consoleManager *console.ConsoleManager
	var dirscanModule *dirscan.DirscanModule

	if args.HasModule(string(modulepkg.ModuleDirscan)) {
		logger.Debug("启用目录扫描模块，创建相关组件...")

		// 创建collector
		logger.Debug("创建URL采集器...")
		collectorInstance = dirscan.NewCollector()

		// 创建控制台管理器
		logger.Debug("创建控制台管理器...")
		consoleManager = console.NewConsoleManager(collectorInstance)

		// 创建目录扫描模块
		logger.Debug("创建目录扫描模块...")
		dirscanModule, err = dirscan.NewDirscanModule(collectorInstance)
		if err != nil {
			return nil, fmt.Errorf("创建目录扫描模块失败: %v", err)
		}

		// 应用全局代理设置到目录扫描模块
		if proxyCfg := config.GetProxyConfig(); proxyCfg.UpstreamProxy != "" {
			dirscanModule.SetProxy(proxyCfg.UpstreamProxy)
		}
	} else {
		logger.Debug("未启用目录扫描模块，跳过collector和consoleManager创建")
	}

	// 创建指纹识别插件（如果启用）
	var fingerprintAddon *fpaddon.FingerprintAddon
	if args.HasModule(string(modulepkg.ModuleFinger)) {
		logger.Debug("创建指纹识别插件...")
		fingerprintAddon, err = createFingerprintAddon()
		if err != nil {
			logger.Warnf("指纹识别插件初始化失败: %v", err)
		}
	}

	// 创建认证学习插件（总是创建，用于被动代理模式下的认证学习）
	logger.Debug("创建认证学习插件...")
	authLearningAddon := createAuthLearningAddon()

	// 创建应用程序实例
	app := &CLIApp{
		proxy:             proxyServer,
		collector:         collectorInstance, // 可能为nil
		consoleManager:    consoleManager,    // 可能为nil
		dirscanModule:     dirscanModule,     // 可能为nil
		fingerprintAddon:  fingerprintAddon,  // 可能为nil
		authLearningAddon: authLearningAddon, // 总是存在
		proxyStarted:      false,
		args:              args,
	}

	// 只在有控制台管理器时设置回调
	if consoleManager != nil {
		consoleManager.SetProxyController(app)
		if fingerprintAddon != nil {
			consoleManager.SetFingerprintAddon(fingerprintAddon)
		}
	}

	logger.Debug("应用程序初始化完成")
	return app, nil
}


// createProxy 创建代理服务器
func createProxy() (*proxy.Proxy, error) {
	serverConfig := config.GetServerConfig()
	proxyConfig := config.GetProxyConfig()

	opts := &proxy.Options{
		Addr:              serverConfig.Listen,
		StreamLargeBodies: proxyConfig.StreamLargebody,
		SslInsecure:       proxyConfig.SSLInsecure, // 添加缺失的SSL配置
		Upstream:          proxyConfig.UpstreamProxy,
	}
	return proxy.NewProxy(opts)
}


// createFingerprintAddon 创建指纹识别插件
func createFingerprintAddon() (*fpaddon.FingerprintAddon, error) {
	addon, err := fpaddon.CreateDefaultAddon()
	if err != nil {
		return nil, err
	}

	fpaddon.SetGlobalAddon(addon)
	return addon, nil
}

// createAuthLearningAddon 创建认证学习插件
func createAuthLearningAddon() *auth.AuthLearningAddon {
	addon := auth.NewAuthLearningAddon()

	// 设置回调：与全局配置交互
	addon.SetCallbacks(
		// OnAuthLearned: 更新全局配置
		func(headers map[string]string) {
			// 获取当前的全局自定义头部
			currentHeaders := config.GetCustomHeaders()
			mergedHeaders := make(map[string]string)

			// 先复制现有的头部
			for key, value := range currentHeaders {
				mergedHeaders[key] = value
			}

			// 添加新学习到的Authorization头部（如果不存在的话）
			newHeadersCount := 0
			for key, value := range headers {
				if _, exists := mergedHeaders[key]; !exists {
					mergedHeaders[key] = value
					newHeadersCount++
				}
			}

			// 更新全局配置
			if newHeadersCount > 0 {
				config.SetCustomHeaders(mergedHeaders)
				logger.Debugf("应用了 %d 个新的Authorization头部到全局配置", newHeadersCount)
			}
		},
		// IsAuthSet: 检查是否已设置认证头部
		func() bool {
			return config.HasCustomHeaders()
		},
	)

	logger.Debug("认证学习插件创建成功")
	return addon
}

// startApplication 启动应用程序
func startApplication(args *CLIArgs) error {
	// 启动代理服务器
	if err := app.StartProxy(); err != nil {
		return fmt.Errorf("启动代理服务器失败: %v", err)
	}

	// 启动指纹识别模块
	if args.HasModule(string(modulepkg.ModuleFinger)) && app.fingerprintAddon != nil {
		// 注意：fingerprintAddon是直接的addon，不是模块，需要设置为全局实例
		fpaddon.SetGlobalAddon(app.fingerprintAddon)
		app.fingerprintAddon.Enable()

		// 为被动代理模式创建并注入OutputFormatter
		engine := app.fingerprintAddon.GetEngine()
		if engine != nil {
			engine.GetConfig().ShowSnippet = true // 启用snippet捕获
			
			snippetEnabled := args.VeryVerbose
			ruleEnabled := args.Verbose || args.VeryVerbose
			
			outputFormatter := fpaddon.OutputFormatter(nil)
			if args.JSONOutput {
				outputFormatter = fpaddon.NewJSONOutputFormatter()
			} else {
				outputFormatter = fpaddon.NewConsoleOutputFormatter(
					true,            // logMatches - 被动模式默认输出
					true,            // showSnippet
					ruleEnabled,     // showRules
					snippetEnabled,  // consoleSnippetEnabled
				)
			}
			engine.GetConfig().OutputFormatter = outputFormatter
			logger.Debugf("被动代理模式 OutputFormatter 已注入: %T", outputFormatter)
		}

		// 将指纹识别addon添加到代理服务器
		app.proxy.AddAddon(app.fingerprintAddon)
		logger.Debug("指纹识别模块启动成功")
	}

	// 启动目录扫描模块
	if args.HasModule(string(modulepkg.ModuleDirscan)) && app.dirscanModule != nil {
		if err := app.dirscanModule.Start(); err != nil {
			logger.Errorf("启动目录扫描模块失败: %v", err)
		} else {
			logger.Debug("目录扫描模块启动成功")
		}
	}

	// 执行模块间依赖注入
	if app.fingerprintAddon != nil {
		// [优化] 使用 RequestProcessor 创建统一配置的 HTTP 客户端
		// 这确保被动扫描中的主动探测逻辑（超时、重试、并发）与主动模式一致
		
		// 1. 获取全局请求配置（已应用CLI参数）
		globalReqConfig := config.GetRequestConfig()
		
		// 2. 转换为 processor.RequestConfig
		// 注意：config包和processor包的RequestConfig结构体不同，需要手动映射
		procConfig := requests.GetDefaultConfig()
		
		if globalReqConfig != nil {
			if globalReqConfig.Timeout > 0 {
				procConfig.Timeout = time.Duration(globalReqConfig.Timeout) * time.Second
			}
			if globalReqConfig.Retry > 0 {
				procConfig.MaxRetries = globalReqConfig.Retry
			}
			if globalReqConfig.Threads > 0 {
				procConfig.MaxConcurrent = globalReqConfig.Threads
			}
			if globalReqConfig.RandomUA != nil {
				procConfig.RandomUserAgent = *globalReqConfig.RandomUA
			}
		}
		
		// 3. 始终应用上游代理（如果配置了）
		if proxyCfg := config.GetProxyConfig(); proxyCfg.UpstreamProxy != "" {
			procConfig.ProxyURL = proxyCfg.UpstreamProxy
		}

		// 4. 创建 RequestProcessor
		requestProcessor := requests.NewRequestProcessor(procConfig)
		// 设置模块上下文
		requestProcessor.SetModuleContext("fingerprint-passive")

		// 5. 使用适配器转换为 HTTPClientInterface
		httpClient := newRequestProcessorHTTPClient(requestProcessor)

		// 6. 注入到指纹识别模块
		app.fingerprintAddon.SetHTTPClient(httpClient)
		
		// 7. 设置主动探测的超时时间 (从配置中获取)
		if procConfig.Timeout > 0 {
			// 使用 RequestProcessor 配置中的超时
			app.fingerprintAddon.SetTimeout(procConfig.Timeout)
			logger.Debugf("指纹插件主动探测超时已设置为: %v", procConfig.Timeout)
		}
		
		logger.Debug("统一的RequestProcessor客户端已注入到指纹识别模块")
	}

	logger.Debug("模块启动和依赖注入完成")
	return nil
}

func displayStartupInfo(args *CLIArgs) {
	// 显示模块状态
	fmt.Print(`
		veo@Evilc0de
`)
	logger.Debugf("模块状态:")
	logger.Debugf("指纹识别: %s\n", getModuleStatus(args.HasModule(string(modulepkg.ModuleFinger))))
	logger.Debugf("目录扫描: %s\n", getModuleStatus(args.HasModule(string(modulepkg.ModuleDirscan))))
}

// StartProxy 启动代理服务器
func (app *CLIApp) StartProxy() error {
	if app.proxyStarted {
		return nil
	}

	// 总是添加认证学习插件（用于被动代理模式下的认证学习）
	if app.authLearningAddon != nil {
		app.proxy.AddAddon(app.authLearningAddon)
		logger.Debug("认证学习插件已添加到代理服务器")
	}

	// 只在启用目录扫描模块时添加collector
	if app.args.HasModule(string(modulepkg.ModuleDirscan)) && app.collector != nil {
		app.proxy.AddAddon(app.collector)
	}

	// 根据启用的模块添加插件
	if app.args.HasModule(string(modulepkg.ModuleFinger)) && app.fingerprintAddon != nil {
		app.proxy.AddAddon(app.fingerprintAddon)
	}

	// 启动代理服务器
	go func() {
		if err := app.proxy.Start(); err != nil {
			logger.Error(err)
		}
	}()

	app.proxyStarted = true
	return nil
}

// StopProxy 停止代理服务器
func (app *CLIApp) StopProxy() error {
	if !app.proxyStarted {
		return nil
	}

	if err := app.proxy.Close(); err != nil {
		return err
	}

	app.proxyStarted = false
	return nil
}

// IsProxyStarted 检查代理是否已启动
func (app *CLIApp) IsProxyStarted() bool {
	return app.proxyStarted
}

// GetFingerprintAddon 获取指纹识别插件
func (app *CLIApp) GetFingerprintAddon() *fpaddon.FingerprintAddon {
	return app.fingerprintAddon
}

// getModuleStatus 获取模块状态文本
func getModuleStatus(enabled bool) string {
	if enabled {
		return "[√]"
	}
	return "[X]"
}

// waitForSignal 等待中断信号或用户输入
func waitForSignal() {
	// 创建信号通道
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 键盘输入通道 (支持按回车触发扫描)
	inputChan := make(chan struct{})
	go func() {
		// 读取标准输入
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				// 如果stdin关闭或出错，退出输入监听
				return
			}
			// 只有按回车才触发
			if buf[0] == '\n' {
				inputChan <- struct{}{}
			}
		}
	}()

	logger.Info("按 [Enter] 键开始扫描收集到的目标...")

	for {
		select {
		case sig := <-sigChan:
			fmt.Println()
			logger.Info(sig)
			cleanup()
			return
		case <-inputChan:
			if app != nil {
				app.triggerScan()
			}
		}
	}
}

// triggerScan 触发被动模式下的目录扫描
func (app *CLIApp) triggerScan() {
	logger.Info("用户触发扫描...")

	if app.dirscanModule == nil {
		logger.Warn("目录扫描模块未启用，无法执行扫描")
		return
	}

	addon := app.dirscanModule.GetAddon()
	if addon == nil {
		logger.Error("目录扫描Addon未初始化")
		return
	}

	// 检查是否有收集到URL
	if len(addon.GetCollectedURLs()) == 0 {
		logger.Warn("没有收集到待扫描的URL，请先浏览目标网站")
		return
	}

	// 暂停指纹识别插件（如果存在），避免扫描流量干扰指纹识别
	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Disable()
		logger.Debug("指纹识别插件已暂停")
	}

	// 执行扫描
	// TriggerScan 会自动暂停收集，扫描完成后恢复收集
	logger.Info("开始执行目录扫描...")
	result, err := addon.TriggerScan()
	if err != nil {
		logger.Errorf("扫描执行失败: %v", err)
	} else {
		logger.Infof("扫描完成，发现 %d 个有效结果", len(result.FilterResult.ValidPages))
	}

	// 恢复指纹识别插件
	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Enable()
		logger.Debug("指纹识别插件已恢复")
	}

	// 报告生成逻辑 (集成到被动扫描)
	// 如果指定了 -o 输出路径，则在扫描结束后生成报告
	if app.args.Output != "" {
		// 收集扫描参数 (模拟)
		scanParams := map[string]interface{}{
			"threads":                   0, // 被动模式此项可能不准确
			"timeout":                   0,
			"retry":                     0,
			"dir_targets_count":         len(result.ScanURLs),
			"fingerprint_targets_count": 0,
			"fingerprint_rules_loaded":  0,
		}

		// 获取指纹引擎
		var fpEngine *fingerprint.Engine
		if app.fingerprintAddon != nil {
			fpEngine = app.fingerprintAddon.GetEngine()
			if fpEngine != nil {
				stats := fpEngine.GetStats()
				scanParams["fingerprint_rules_loaded"] = stats.RulesLoaded
			}
		}

		// 构造配置
		reportConfig := &ReportConfig{
			Modules:                app.args.Modules,
			OutputPath:             app.args.Output,
			ShowFingerprintSnippet: app.args.VeryVerbose,
			ScanParams:             scanParams,
		}

		// 准备数据
		// dirscan结果来自 TriggerScan 返回值
		// finger结果目前需要从 FingerprintEngine 获取所有匹配项 (因为是被动实时匹配的)
		// 注意：这可能包含非本次扫描周期的指纹，但在被动模式下，报告通常反映当前会话的所有发现
		// 更好的做法可能是让 FingerprintAddon 支持 Session 级别的匹配收集，但目前先使用全局匹配
		var dirResults, fingerResults []interfaces.HTTPResponse
		// Convert pointer slice to value slice for GenerateReport
		for _, p := range result.FilterResult.ValidPages {
			if p != nil {
				dirResults = append(dirResults, *p)
			}
		}

		// 如果没有明确的 FingerprintResults 结构，我们通过 filterResult.ValidPages 来获取
		// 但对于 JSON 报告，我们需要独立的 fingerResults 列表
		// 目前被动模式没有维护独立的 fingerResults 列表，我们暂时留空，或者尝试从 ValidPages 中提取（如果它们包含指纹）
		// 为了简单起见，我们假定指纹信息主要通过 Matches 列表 (JSON) 或 ValidPages.Fingerprints (Excel) 体现

		// 调用统一的报告生成函数
		err := GenerateReport(reportConfig, dirResults, fingerResults, result.FilterResult, fpEngine)
		if err != nil {
			logger.Errorf("报告生成失败: %v", err)
		}
	}

	logger.Info("等待下一轮收集，按 [Enter] 键再次扫描...")
}

// cleanup 清理资源
func cleanup() {

	if app != nil {
		// 停止目录扫描模块
		if app.dirscanModule != nil {
			if err := app.dirscanModule.Stop(); err != nil {
				logger.Errorf("停止目录扫描模块失败: %v", err)
			}
		}

		// 停止代理服务器
		if err := app.StopProxy(); err != nil {
			logger.Errorf("停止代理服务器失败: %v", err)
		}
	}

	// 等待清理完成
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

// runActiveScanMode 运行主动扫描模式

func runActiveScanMode(args *CLIArgs) error {
	logger.Debug("启动主动扫描模式")

	// [修复] 使用已经应用了CLI参数的全局配置，而不是重新加载配置文件
	// 这样可以确保CLI参数（如-t线程数）能够正确生效
	cfg := config.GetConfig()

	// 创建扫描控制器并运行
	scanner := NewScanController(args, cfg)
	return scanner.Run()
}

