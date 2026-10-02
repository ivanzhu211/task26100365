package vulndedup

import "testing"

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		index int
		want  string
	}{
		{
			name:  "scheme host case default port dot segments tilde fragment",
			raw:   "http://EXAMPLE.test:80/a/%2e%2e/b?q=one&x=%7e",
			index: 1,
			want:  "http://example.test/b?q=&x=~",
		},
		{
			name:  "trailing dot in host kept",
			raw:   "https://example.test.:443/p?q=1",
			index: 1,
			want:  "https://example.test./p?q=",
		},
		{
			name:  "non default port kept numerically",
			raw:   "http://example.test:8080/p?q=1",
			index: 1,
			want:  "http://example.test:8080/p?q=",
		},
		{
			name:  "leading zero port equals default",
			raw:   "http://example.test:080/p?q=1",
			index: 1,
			want:  "http://example.test/p?q=",
		},
		{
			name:  "empty path is root",
			raw:   "http://example.test?q=1",
			index: 1,
			want:  "http://example.test/?q=",
		},
		{
			name:  "escaped slash not decoded",
			raw:   "http://example.test/a%2fb?q=1",
			index: 1,
			want:  "http://example.test/a%2Fb?q=",
		},
		{
			name:  "plus kept and space escape uppercased",
			raw:   "http://example.test/p?x=a+b&y=a%20b&q=1",
			index: 3,
			want:  "http://example.test/p?x=a+b&y=a%20b&q=",
		},
		{
			name:  "encoded separator does not split",
			raw:   "http://example.test/p?x=1%262&y=z",
			index: 2,
			want:  "http://example.test/p?x=1%262&y=",
		},
		{
			name:  "empty items and missing equals kept",
			raw:   "http://example.test/p?a=1&&b&c=&q=9",
			index: 5,
			want:  "http://example.test/p?a=1&&b&c=&q=",
		},
		{
			name:  "tested item without equals keeps name only",
			raw:   "http://example.test/p?a=1&flag",
			index: 2,
			want:  "http://example.test/p?a=1&flag",
		},
		{
			name:  "split on first equals only",
			raw:   "http://example.test/p?x=a=b=c&q=1",
			index: 2,
			want:  "http://example.test/p?x=a=b=c&q=",
		},
		{
			name:  "dot segments current and parent",
			raw:   "http://example.test/a/./b/../c?q=1",
			index: 1,
			want:  "http://example.test/a/c?q=",
		},
		{
			name:  "dot segments cannot escape root",
			raw:   "http://example.test/../../a?q=1",
			index: 1,
			want:  "http://example.test/a?q=",
		},
		{
			name:  "trailing dot segment means directory",
			raw:   "http://example.test/a/b/..?q=1",
			index: 1,
			want:  "http://example.test/a/?q=",
		},
		{
			name:  "consecutive slashes and trailing slash kept",
			raw:   "http://example.test/a//b/?q=1",
			index: 1,
			want:  "http://example.test/a//b/?q=",
		},
		{
			name:  "double dot pops empty segment from double slash",
			raw:   "http://example.test/a//../b?q=1",
			index: 1,
			want:  "http://example.test/a/b?q=",
		},
		{
			name:  "path case sensitive",
			raw:   "http://example.test/Ab%63?q=1",
			index: 1,
			want:  "http://example.test/Abc?q=",
		},
		{
			name:  "no recursive decoding",
			raw:   "http://example.test/p?x=%257e&q=1",
			index: 2,
			want:  "http://example.test/p?x=%257e&q=",
		},
		{
			name:  "duplicate names kept in order",
			raw:   "http://example.test/p?a=1&a=2&q=3",
			index: 3,
			want:  "http://example.test/p?a=1&a=2&q=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeURL(tc.raw, tc.index)
			if err != nil {
				t.Fatalf("normalizeURL(%q, %d) error: %v", tc.raw, tc.index, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeURL(%q, %d) = %q, want %q", tc.raw, tc.index, got, tc.want)
			}
		})
	}
}

func TestNormalizeURLIndexOutOfRange(t *testing.T) {
	if _, err := normalizeURL("http://example.test/?q=1", 2); err == nil {
		t.Fatal("expected error for out-of-range query index")
	}
	if _, err := normalizeURL("http://example.test/?q=1", 0); err == nil {
		t.Fatal("expected error for zero query index")
	}
}
