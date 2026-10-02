package vulndedup

import (
	"errors"
	"fmt"
)

// ErrDuplicateID 表示同一个发现编号被重复提交。
var ErrDuplicateID = errors.New("vulndedup: duplicate finding id")

// Store 是进程内的漏洞发现归并库，不是并发安全的；
// 需要并发调用时由上层扫描器自行加锁。
type Store struct {
	seen   map[string]struct{}
	groups map[GroupKey]*Group
	order  []GroupKey
}

// NewStore 创建一个空的归并库。
func NewStore() *Store {
	return &Store{
		seen:   make(map[string]struct{}),
		groups: make(map[GroupKey]*Group),
	}
}

// Submit 提交一批发现。批次划分和提交顺序不影响最终分组与成员集合。
// 若某条发现的编号已提交过，或 URL 无法规范化，返回错误且该批次不做任何修改。
func (s *Store) Submit(findings []Finding) error {
	type pending struct {
		finding Finding
		key     GroupKey
	}
	batch := make([]pending, 0, len(findings))
	batchSeen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if _, ok := s.seen[f.ID]; ok {
			return fmt.Errorf("%w: %q", ErrDuplicateID, f.ID)
		}
		if _, ok := batchSeen[f.ID]; ok {
			return fmt.Errorf("%w: %q", ErrDuplicateID, f.ID)
		}
		batchSeen[f.ID] = struct{}{}
		norm, err := normalizeURL(f.RawURL, f.QueryIndex)
		if err != nil {
			return fmt.Errorf("vulndedup: finding %q: %w", f.ID, err)
		}
		batch = append(batch, pending{
			finding: f,
			key: GroupKey{
				Target:        f.Target,
				CWE:           f.CWE,
				QueryIndex:    f.QueryIndex,
				NormalizedURL: norm,
			},
		})
	}
	for _, p := range batch {
		s.seen[p.finding.ID] = struct{}{}
		g, ok := s.groups[p.key]
		if !ok {
			g = &Group{Key: p.key}
			s.groups[p.key] = g
			s.order = append(s.order, p.key)
		}
		g.Members = append(g.Members, p.finding)
	}
	return nil
}

// Groups 返回当前全部归并结果，按组首次出现的顺序排列。
// 每个成员保留提交时的原始发现，可用于人工复现。
func (s *Store) Groups() []Group {
	out := make([]Group, 0, len(s.order))
	for _, key := range s.order {
		g := s.groups[key]
		members := make([]Finding, len(g.Members))
		copy(members, g.Members)
		out = append(out, Group{Key: g.Key, Members: members})
	}
	return out
}
