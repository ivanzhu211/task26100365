package vulnmerge

import (
	"sort"
	"testing"
)

// groupOf 返回包含指定编号发现的组。
func groupOf(t *testing.T, s *Store, id string) Group {
	t.Helper()
	for _, g := range s.Groups() {
		for _, f := range g.Findings {
			if f.ID == id {
				return g
			}
		}
	}
	t.Fatalf("finding %q not found in any group", id)
	return Group{}
}

func memberIDs(g Group) []string {
	ids := make([]string, 0, len(g.Findings))
	for _, f := range g.Findings {
		ids = append(ids, f.ID)
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

// 相同目标和 CWE 下，两条 URL 指定第 1 项时必须归并，并保留两条原始 URL。
func TestMergeEquivalentURLs(t *testing.T) {
	s := NewStore()
	f1 := Finding{ID: "f1", Target: "t1", CWE: "CWE-89",
		RawURL: "http://EXAMPLE.test:80/a/%2e%2e/b?q=one&x=%7e", TestedIndex: 1}
	f2 := Finding{ID: "f2", Target: "t1", CWE: "CWE-89",
		RawURL: "http://example.test/b?q=two&x=~#proof", TestedIndex: 1}
	if _, err := s.Submit(f1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(f2); err != nil {
		t.Fatal(err)
	}

	gs := s.Groups()
	if len(gs) != 1 {
		t.Fatalf("expected 1 group, got %d", len(gs))
	}
	g := gs[0]
	if !equalIDs(memberIDs(g), []string{"f1", "f2"}) {
		t.Fatalf("unexpected members: %v", memberIDs(g))
	}
	// 原始 URL 原样保留，未被规范化改写。
	raws := map[string]bool{}
	for _, f := range g.Findings {
		raws[f.RawURL] = true
	}
	if !raws[f1.RawURL] || !raws[f2.RawURL] {
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
			name: "转义斜杠与字面量斜杠",
			a:    Finding{ID: "a", Target: "t", CWE: "CWE-1", RawURL: "http://h/a%2Fb?q=1", TestedIndex: 1},
			b:    Finding{ID: "b", Target: "t", CWE: "CWE-1", RawURL: "http://h/a/b?q=2", TestedIndex: 1},
		},
		{
			name: "未被测项中的加号与%20",
			a:    Finding{ID: "a", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?q=1&x=a+b", TestedIndex: 1},
			b:    Finding{ID: "b", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?q=2&x=a%20b", TestedIndex: 1},
		},
		{
			name: "编码分隔符与真实分隔符",
			a:    Finding{ID: "a", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?q=1&x=a%26y%3Dz", TestedIndex: 1},
			b:    Finding{ID: "b", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?q=2&x=a&y=z", TestedIndex: 1},
		},
		{
			name: "同一URL两个同名参数分别被测",
			a:    Finding{ID: "a", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?a=1&a=2", TestedIndex: 1},
			b:    Finding{ID: "b", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?a=1&a=2", TestedIndex: 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			if _, err := s.Submit(tc.a); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Submit(tc.b); err != nil {
				t.Fatal(err)
			}
			if n := len(s.Groups()); n != 2 {
				t.Fatalf("expected 2 groups, got %d", n)
			}
		})
	}
}

// 批次划分和提交顺序不得改变最终分组或成员集合。
func TestBatchOrderInvariance(t *testing.T) {
	findings := []Finding{
		{ID: "1", Target: "t", CWE: "CWE-89", RawURL: "http://EXAMPLE.test:80/a/%2e%2e/b?q=one&x=%7e", TestedIndex: 1},
		{ID: "2", Target: "t", CWE: "CWE-89", RawURL: "http://example.test/b?q=two&x=~#proof", TestedIndex: 1},
		{ID: "3", Target: "t", CWE: "CWE-89", RawURL: "http://example.test/other?q=z", TestedIndex: 1},
		{ID: "4", Target: "t", CWE: "CWE-79", RawURL: "http://example.test/b?q=three&x=~", TestedIndex: 1},
		{ID: "5", Target: "t", CWE: "CWE-89", RawURL: "HTTP://example.test./b?q=four&x=%7E", TestedIndex: 1},
	}

	// 一次性按原序提交。
	s1 := NewStore()
	if err := s1.SubmitBatch(findings); err != nil {
		t.Fatal(err)
	}

	// 逆序、拆成多批提交。
	s2 := NewStore()
	rev := make([]Finding, len(findings))
	for i, f := range findings {
		rev[len(findings)-1-i] = f
	}
	if err := s2.SubmitBatch(rev[:2]); err != nil {
		t.Fatal(err)
	}
	if err := s2.SubmitBatch(rev[2:]); err != nil {
		t.Fatal(err)
	}

	g1, g2 := s1.Groups(), s2.Groups()
	if len(g1) != len(g2) {
		t.Fatalf("group count differs: %d vs %d", len(g1), len(g2))
	}
	sets1 := map[string][]string{}
	for _, g := range g1 {
		sets1[g.Key] = memberIDs(g)
	}
	for _, g := range g2 {
		want, ok := sets1[g.Key]
		if !ok {
			t.Fatalf("group %q missing in single-batch run", g.Key)
		}
		if !equalIDs(want, memberIDs(g)) {
			t.Fatalf("members differ for %q: %v vs %v", g.Key, want, memberIDs(g))
		}
	}
	// 末尾圆点保留：id=5 的主机带圆点，不与 id=1/2 归并。
	if len(g1) != 4 {
		t.Fatalf("expected 4 groups, got %d", len(g1))
	}
}

// 每个编号只提交一次，重复提交被忽略。
func TestDuplicateIDIgnored(t *testing.T) {
	s := NewStore()
	f := Finding{ID: "dup", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?q=1", TestedIndex: 1}
	ok, err := s.Submit(f)
	if err != nil || !ok {
		t.Fatalf("first submit: ok=%v err=%v", ok, err)
	}
	ok, err = s.Submit(Finding{ID: "dup", Target: "t", CWE: "CWE-1", RawURL: "http://h/p?q=2", TestedIndex: 1})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("duplicate ID should not be accepted")
	}
	gs := s.Groups()
	if len(gs) != 1 || len(gs[0].Findings) != 1 {
		t.Fatalf("duplicate ID changed groups: %+v", gs)
	}
}
