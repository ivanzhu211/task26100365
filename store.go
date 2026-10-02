package vulnmerge

import (
	"fmt"
	"strconv"
	"strings"
)

// Finding 表示上层扫描器提交的一条发现。
type Finding struct {
	ID          string // 唯一编号，每个编号只提交一次
	Target      string // 目标标识
	CWE         string // CWE 编号
	RawURL      string // 原始 URL，原样保留用于复现
	TestedIndex int    // 被测查询项序号，从 1 开始，包含空查询项
}

// Group 表示归并后的一组同源发现。
type Group struct {
	Key      string    // 归并键
	Findings []Finding // 组内成员，保留原始 URL
}

// Store 为进程内的漏洞发现归并库。
type Store struct {
	groups map[string]*Group
	order  []string // 组首次出现的顺序
	seen   map[string]bool
}

// NewStore 创建一个空的归并库。
func NewStore() *Store {
	return &Store{
		groups: make(map[string]*Group),
		seen:   make(map[string]bool),
	}
}

// groupKey 计算归并键：目标标识、CWE、被测项序号以及
// 排除被测值后的规范化 URL 全部相同才属于同一漏洞。
func groupKey(f Finding) (string, error) {
	norm, err := normalizeURL(f.RawURL, f.TestedIndex)
	if err != nil {
		return "", fmt.Errorf("finding %q: %w", f.ID, err)
	}
	var b strings.Builder
	b.WriteString(f.Target)
	b.WriteByte('\x1f')
	b.WriteString(f.CWE)
	b.WriteByte('\x1f')
	b.WriteString(strconv.Itoa(f.TestedIndex))
	b.WriteByte('\x1f')
	b.WriteString(norm)
	return b.String(), nil
}

// Submit 提交一条发现；编号重复时忽略并返回 false。
func (s *Store) Submit(f Finding) (bool, error) {
	if s.seen[f.ID] {
		return false, nil
	}
	key, err := groupKey(f)
	if err != nil {
		return false, err
	}
	s.seen[f.ID] = true
	g, ok := s.groups[key]
	if !ok {
		g = &Group{Key: key}
		s.groups[key] = g
		s.order = append(s.order, key)
	}
	g.Findings = append(g.Findings, f)
	return true, nil
}

// SubmitBatch 分批提交一批发现；批次划分不影响最终分组。
func (s *Store) SubmitBatch(fs []Finding) error {
	for _, f := range fs {
		if _, err := s.Submit(f); err != nil {
			return err
		}
	}
	return nil
}

// Groups 按首次出现顺序返回当前全部归并结果。
func (s *Store) Groups() []Group {
	out := make([]Group, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, *s.groups[key])
	}
	return out
}
