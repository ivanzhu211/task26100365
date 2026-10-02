// Package vulndedup 提供漏洞发现归并能力，由上层扫描器调用。
// 数据保存在进程内，支持分批提交发现和读取归并结果。
package vulndedup

// Finding 表示一条漏洞发现。
type Finding struct {
	// ID 是发现的唯一编号，每个编号只允许提交一次。
	ID string
	// Target 是目标标识（由上层扫描器定义，例如任务或资产 ID）。
	Target string
	// CWE 是漏洞类型编号，例如 "CWE-79"。
	CWE string
	// RawURL 是产生该发现时的原始 URL，必须是合法的绝对 HTTP/HTTPS 地址。
	RawURL string
	// QueryIndex 是被测查询项的序号，从 1 开始，包含空查询项。
	QueryIndex int
}

// Group 表示一组被归并为同一漏洞的发现。
type Group struct {
	// Key 是归并键：目标标识、CWE、被测项序号以及排除被测值后的规范化 URL。
	Key GroupKey
	// Members 是组内全部成员，保留原始发现用于复现。
	Members []Finding
}

// GroupKey 是漏洞身份的全部组成要素。
type GroupKey struct {
	Target     string
	CWE        string
	QueryIndex int
	// NormalizedURL 是排除被测查询项的值之后的规范化 URL。
	NormalizedURL string
}
