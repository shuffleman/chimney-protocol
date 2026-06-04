// Package dilution 为稀释流提供真实内容块。
//
// 稀释帧携带预录的 HTTP 响应内容（HTML、CSS、JS、JSON）
// 而非随机字节。这使得流量在 DPI 分析下与真实网页浏览
// 在语义上不可区分。内容块从白名单站点的真实 HTTPS 会话
// 抓取的 JSON 文件中加载。
package dilution

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Block 表示单个抓取的 HTTP 响应块及其大小。
type Block struct {
	Size    int    `json:"size"`
	Content string `json:"content"` // base64 编码的内容
}

// Provider 管理预录的内容块，并选择适合的块来匹配目标记录大小。
type Provider struct {
	blocks []Block
}

// NewProvider 从块切片创建一个 Provider。
func NewProvider(blocks []Block) *Provider {
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i].Size < blocks[j].Size
	})
	return &Provider{blocks: blocks}
}

// LoadProviderFromFile 从 JSON 文件加载内容块。
// 文件格式是 Block 对象的 JSON 数组，内容为 base64 编码。
func LoadProviderFromFile(path string) (*Provider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dilution: read file: %w", err)
	}

	var rawBlocks []Block
	if err := json.Unmarshal(data, &rawBlocks); err != nil {
		return nil, fmt.Errorf("dilution: parse blocks: %w", err)
	}

	// 解码 base64 内容并更新大小为解码后的长度。
	for i := range rawBlocks {
		decoded, err := base64.StdEncoding.DecodeString(rawBlocks[i].Content)
		if err != nil {
			return nil, fmt.Errorf("dilution: decode block %d: %w", i, err)
		}
		rawBlocks[i].Content = string(decoded)
		rawBlocks[i].Size = len(decoded)
	}

	return NewProvider(rawBlocks), nil
}

// GetBlock 返回编码大小接近 targetSize 的内容块。
// 返回适合 targetSize（减去 H2 帧头 9 字节）的最大块，
// 如果未找到精确匹配，则查找 targetSize 80% 以上的块。
func (p *Provider) GetBlock(targetSize uint16) []byte {
	if len(p.blocks) == 0 {
		return nil
	}

	// 块的帧（9 字节头 + 内容）需要适合 targetSize。
	// 因此最大内容大小 = targetSize - 9。
	maxContent := int(targetSize) - 9
	if maxContent <= 0 {
		return nil
	}

	// 找到适合 maxContent 的最大块。
	// 将大小在 maxContent 的 20% 以内的块视为可接受的匹配。
	minContent := int(float64(maxContent) * 0.8)

	// 尝试找到精确匹配的块：大小 <= maxContent 但尽可能大。
	var best Block
	for _, b := range p.blocks {
		if b.Size <= maxContent && b.Size > best.Size {
			best = b
		}
	}

	// 如果最佳匹配太小（小于 maxContent 的 80%），则使用
	// 最大可用块，让调用者填充剩余部分。
	if best.Size < minContent && len(p.blocks) > 0 {
		best = p.blocks[len(p.blocks)-1] // largest block available
		if best.Size > maxContent {
			// 防截断：选择适合的最大块
			best = Block{}
			for _, b := range p.blocks {
				if b.Size <= maxContent && b.Size > best.Size {
					best = b
				}
			}
		}
	}

	if best.Size == 0 {
		// 没有任何块适合
		return nil
	}

	return []byte(best.Content)
}

// Len 返回 provider 中的块数量。
func (p *Provider) Len() int {
	return len(p.blocks)
}
