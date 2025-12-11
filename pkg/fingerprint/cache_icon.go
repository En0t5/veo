package fingerprint

import (
	"crypto/md5"
	"fmt"
	"sync"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
)

// IconCache 图标缓存管理组件
// 负责缓存图标哈希值和匹配结果，避免重复请求和计算
type IconCache struct {
	hashCache  map[string]string // 图标URL -> MD5哈希值 (包括 "FAILED" 状态)
	matchCache map[string]bool   // 缓存键(URL+Hash) -> 匹配结果
	mu         sync.RWMutex      // 读写锁
}

// NewIconCache 创建新的图标缓存实例
func NewIconCache() *IconCache {
	return &IconCache{
		hashCache:  make(map[string]string),
		matchCache: make(map[string]bool),
	}
}

// GetHash 获取图标哈希值（带缓存）
// 如果缓存未命中，使用提供的 client 发起请求并计算哈希
func (c *IconCache) GetHash(iconURL string, client httpclient.HTTPClientInterface) (string, error) {
	// 1. 检查缓存
	c.mu.RLock()
	cachedValue, exists := c.hashCache[iconURL]
	c.mu.RUnlock()

	if exists {
		// 检查是否为失败缓存
		if cachedValue == "FAILED" {
			logger.Debugf("图标失败缓存命中: %s (之前请求失败)", iconURL)
			return "", fmt.Errorf("图标请求失败（缓存结果）")
		}
		// 成功缓存命中
		logger.Debugf("图标成功缓存命中: %s -> %s", iconURL, cachedValue)
		return cachedValue, nil
	}

	// 2. 缓存未命中，发起请求
	if client == nil {
		return "", fmt.Errorf("HTTP客户端为空，无法请求图标")
	}

	logger.Debugf("图标缓存未命中，开始请求: %s", iconURL)
	body, statusCode, err := client.MakeRequest(iconURL)

	// 3. 处理请求结果
	if err != nil {
		c.setHashCache(iconURL, "FAILED")
		logger.Debugf("图标网络请求失败并缓存: %s, 错误: %v", iconURL, err)
		return "", fmt.Errorf("请求图标失败: %v", err)
	}

	if statusCode != 200 {
		c.setHashCache(iconURL, "FAILED")
		logger.Debugf("图标HTTP错误并缓存: %s, 状态码: %d", iconURL, statusCode)
		return "", fmt.Errorf("图标请求返回非200状态码: %d", statusCode)
	}

	// 4. 计算哈希并缓存
	hash := fmt.Sprintf("%x", md5.Sum([]byte(body)))
	c.setHashCache(iconURL, hash)
	logger.Debugf("图标哈希计算并缓存: %s -> %s", iconURL, hash)

	return hash, nil
}

// setHashCache 设置哈希缓存（线程安全）
func (c *IconCache) setHashCache(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hashCache[key] = value
}

// GetMatchResult 获取匹配结果缓存
func (c *IconCache) GetMatchResult(iconURL, expectedHash string) (bool, bool) {
	key := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, exists := c.matchCache[key]
	return result, exists
}

// SetMatchResult 设置匹配结果缓存
func (c *IconCache) SetMatchResult(iconURL, expectedHash string, match bool) {
	key := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.matchCache[key] = match
}

// buildMatchCacheKey 构建匹配缓存键
func (c *IconCache) buildMatchCacheKey(iconURL, expectedHash string) string {
	return iconURL + "||" + expectedHash
}

// Clear 清空缓存
func (c *IconCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hashCache = make(map[string]string)
	c.matchCache = make(map[string]bool)
}
