package vulndedup

import (
	"errors"
	"sort"
	"testing"
)

func finding(id, target, cwe, rawURL string, index int) Finding {
	return Finding{ID: id, Target: target, CWE: cwe, RawURL: rawURL, QueryIndex: index}
}

// groupOf 返回包含指定成员编号的组。
func groupOf(groups []Group, id string) *Group {
	for i := range groups {
		for _, m := range groups[i].Members {
			if m.ID == id {
				return &groups[i]
			}
		}
	}
	return nil
}

func memberIDs(g *Group) []string {
	ids := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return ids
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 必须归并：只有被测项的值不同，其余差异都属于规范化应消除的范围。
func TestMergeEquivalentFindings(t *testing.T) {
	s := NewStore()
	err := s.Submit([]Finding{
		finding("f1", "target-1", "CWE-79", "http://EXAMPLE.test:80/a/%2e%2e/b?q=one&x=%7e", 1),
		finding("f2", "target-1", "CWE-79", "http://example.test/b?q=two&x=~#proof", 1),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	groups := s.Groups()
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	g := groupOf(groups, "f1")
	if !equalIDs(memberIDs(g), []string{"f1", "f2"}) {
		t.Fatalf("members = %v, want [f1 f2]", memberIDs(g))
	}
	// 原始 URL 必须原样保留，用于人工复现。
	raws := map[string]bool{}
	for _, m := range g.Members {
		raws[m.RawURL] = true
	}
	if !raws["http://EXAMPLE.test:80/a/%2e%2e/b?q=one&x=%7e"] ||
		!raws["http://example.test/b?q=two&x=~#proof"] {
		t.Fatalf("raw URLs not preserved: %v", raws)
	}
}

// 不能归并的近似输入。
func TestNoMergeNearMisses(t *testing.T) {
	cases := []struct {
		name string
		a, b Finding
	}{
		{
			name: "escaped slash vs literal slash",
			a:    finding("a", "t", "CWE-1", "http://example.test/a%2Fb?q=1", 1),
			b:    finding("b", "t", "CWE-1", "http://example.test/a/b?q=2", 1),
		},
		{
			name: "plus vs escaped space in untested item",
			a:    finding("a", "t", "CWE-1", "http://example.test/p?x=a+b&q=1", 2),
			b:    finding("b", "t", "CWE-1", "http://example.test/p?x=a%20b&q=2", 2),
		},
		{
			name: "encoded separator vs real separator",
			a:    finding("a", "t", "CWE-1", "http://example.test/p?x=1%262&q=1", 2),
			b:    finding("b", "t", "CWE-1", "http://example.test/p?x=1&2&q=2", 3),
		},
		{
			name: "same-name params tested at different positions",
			a:    finding("a", "t", "CWE-1", "http://example.test/p?a=1&a=2", 1),
			b:    finding("b", "t", "CWE-1", "http://example.test/p?a=1&a=2", 2),
		},
		{
			name: "different cwe",
			a:    finding("a", "t", "CWE-1", "http://example.test/p?q=1", 1),
			b:    finding("b", "t", "CWE-2", "http://example.test/p?q=2", 1),
		},
		{
			name: "different target",
			a:    finding("a", "t1", "CWE-1", "http://example.test/p?q=1", 1),
			b:    finding("b", "t2", "CWE-1", "http://example.test/p?q=2", 1),
		},
		{
			name: "untested item value differs",
			a:    finding("a", "t", "CWE-1", "http://example.test/p?x=1&q=a", 2),
			b:    finding("b", "t", "CWE-1", "http://example.test/p?x=2&q=b", 2),
		},
		{
			name: "equals sign presence differs",
			a:    finding("a", "t", "CWE-1", "http://example.test/p?x&q=1", 2),
			b:    finding("b", "t", "CWE-1", "http://example.test/p?x=&q=2", 2),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			if err := s.Submit([]Finding{tc.a, tc.b}); err != nil {
				t.Fatalf("Submit: %v", err)
			}
			groups := s.Groups()
			if len(groups) != 2 {
				t.Fatalf("got %d groups, want 2: %+v", len(groups), groups)
			}
		})
	}
}

// 同一 URL 中两个同名参数分别被测，必须各自成组。
func TestSameURLDifferentOccurrences(t *testing.T) {
	s := NewStore()
	raw := "http://example.test/p?a=1&a=2"
	if err := s.Submit([]Finding{
		finding("first", "t", "CWE-1", raw, 1),
		finding("second", "t", "CWE-1", raw, 2),
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	groups := s.Groups()
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
}

// 批次划分和提交顺序不得改变最终分组与成员集合。
func TestBatchAndOrderInvariance(t *testing.T) {
	findings := []Finding{
		finding("f1", "t", "CWE-1", "http://EXAMPLE.test:80/a/%2e%2e/b?q=one&x=%7e", 1),
		finding("f2", "t", "CWE-1", "http://example.test/b?q=two&x=~#proof", 1),
		finding("f3", "t", "CWE-1", "http://example.test/other?q=z", 1),
		finding("f4", "t", "CWE-2", "http://example.test/b?q=three&x=~", 1),
	}
	signature := func(groups []Group) map[string][]string {
		out := map[string][]string{}
		for _, g := range groups {
			key := g.Key.CWE + "|" + g.Key.NormalizedURL
			out[key] = memberIDs(&g)
		}
		return out
	}

	single := NewStore()
	if err := single.Submit(findings); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	want := signature(single.Groups())

	// 逐条提交，且顺序打乱。
	shuffled := NewStore()
	for _, i := range []int{2, 0, 3, 1} {
		if err := shuffled.Submit([]Finding{findings[i]}); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	got := signature(shuffled.Groups())

	if len(got) != len(want) {
		t.Fatalf("group count = %d, want %d", len(got), len(want))
	}
	for key, ids := range want {
		if !equalIDs(got[key], ids) {
			t.Fatalf("group %q members = %v, want %v", key, got[key], ids)
		}
	}
}

// 重复编号必须被拒绝，且整批不产生副作用。
func TestDuplicateIDRejected(t *testing.T) {
	s := NewStore()
	if err := s.Submit([]Finding{
		finding("f1", "t", "CWE-1", "http://example.test/p?q=1", 1),
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	err := s.Submit([]Finding{
		finding("f2", "t", "CWE-1", "http://example.test/p?q=2", 1),
		finding("f1", "t", "CWE-1", "http://example.test/p?q=3", 1),
	})
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("err = %v, want ErrDuplicateID", err)
	}
	if got := len(s.Groups()); got != 1 {
		t.Fatalf("groups = %d, want 1 (failed batch must be atomic)", got)
	}
}
