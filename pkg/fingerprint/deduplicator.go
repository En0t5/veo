package fingerprint

import (
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Deduplicator 结果去重器接口
// 用于防止重复输出相同的指纹识别结果
type Deduplicator interface {
	// ShouldOutput 检查是否应该输出（去重）
	// 返回 true 表示应该输出（首次出现），false 表示已重复
	ShouldOutput(urlStr string, fingerprintNames []string) bool
	
	// Clear 清空去重缓存
	Clear()
	
	// Count 获取已缓存的项目数量
	Count() int
}

// InMemoryDeduplicator 基于内存的去重器实现
// 线程安全
type InMemoryDeduplicator struct {
	cache map[string]bool
	mu    sync.RWMutex
}

// NewInMemoryDeduplicator 创建新的内存去重器
func NewInMemoryDeduplicator() *InMemoryDeduplicator {
	return &InMemoryDeduplicator{
		cache: make(map[string]bool),
	}
}

// ShouldOutput 实现 Deduplicator 接口
func (d *InMemoryDeduplicator) ShouldOutput(urlStr string, fingerprintNames []string) bool {
	cacheKey := d.generateCacheKey(urlStr, fingerprintNames)

	d.mu.Lock()
	defer d.mu.Unlock()

	// 检查是否已输出
	if d.cache[cacheKey] {
		return false // 已重复,不应输出
	}

	// 标记为已输出
	d.cache[cacheKey] = true
	return true // 应该输出
}

// Clear 实现 Deduplicator 接口
func (d *InMemoryDeduplicator) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache = make(map[string]bool)
}

// Count 实现 Deduplicator 接口
func (d *InMemoryDeduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.cache)
}

// generateCacheKey 生成去重缓存键
// 结合URL和指纹名称生成细粒度的缓存键
func (d *InMemoryDeduplicator) generateCacheKey(rawURL string, fingerprintNames []string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	var builder strings.Builder
	builder.Grow(len(parsedURL.Host) + len(parsedURL.Path) + 50)

	// 添加主机和路径信息
	builder.WriteString(parsedURL.Host)
	builder.WriteByte('|')
	builder.WriteString(parsedURL.Path)
	builder.WriteByte('|')

	// 对指纹名称排序以确保一致性
	if len(fingerprintNames) == 0 {
		return builder.String()
	} else if len(fingerprintNames) == 1 {
		builder.WriteString(fingerprintNames[0])
	} else {
		// 创建排序副本
		sortedNames := make([]string, len(fingerprintNames))
		copy(sortedNames, fingerprintNames)
		sort.Strings(sortedNames)
		builder.WriteString(strings.Join(sortedNames, ","))
	}

	return builder.String()
}
