package vulndedup

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// normalizeURL 对原始 URL 做规范化，并清除第 queryIndex 个查询项（从 1 开始）
// 的值，返回用于身份比较的规范化形式。被测项的名字和等号有无保留。
//
// 规范化规则：
//   - 协议与主机名小写；域名末尾圆点保留；端口按数值比较，省略默认端口。
//   - 忽略片段；空路径视为根路径。
//   - 百分号转义仅解码 ASCII 字母数字及 -._~，其余转义统一十六进制字母为大写。
//   - 解码后的点路径段按 RFC3986 消除，不得越过根目录。
//   - 查询串只按字面量 & 分项、按第一个字面量 = 分名字和值；
//     顺序、重复项、空项、等号有无全部保留；+ 不表示空格。
func normalizeURL(rawURL string, queryIndex int) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("vulndedup: invalid URL %q: %w", rawURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("vulndedup: unsupported scheme %q", u.Scheme)
	}

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(strings.ToLower(u.Hostname()))
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return "", fmt.Errorf("vulndedup: invalid port in %q", rawURL)
		}
		if !isDefaultPort(scheme, n) {
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(n))
		}
	}
	b.WriteString(normalizePath(u.EscapedPath()))
	query, err := normalizeQuery(u.RawQuery, queryIndex)
	if err != nil {
		return "", err
	}
	b.WriteByte('?')
	b.WriteString(query)
	return b.String(), nil
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// normalizePath 规范化转义后的路径：先做转义规范化，再按段消除点段。
// 路径大小写、连续斜杠和普通结尾斜杠均保留。
func normalizePath(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	raw := strings.Split(escapedPath, "/")
	segs := make([]string, len(raw))
	for i, seg := range raw {
		segs[i] = normalizeEscapes(seg)
	}
	// 绝对地址的路径以 "/" 开头，raw[0] 必为空串，作为栈底根段。
	stack := make([]string, 0, len(segs))
	for i, seg := range segs {
		last := i == len(segs)-1
		switch seg {
		case ".":
			if last {
				stack = append(stack, "")
			}
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			if last {
				stack = append(stack, "")
			}
		default:
			stack = append(stack, seg)
		}
	}
	return strings.Join(stack, "/")
}

// normalizeQuery 规范化原始查询串，并清除第 queryIndex 个查询项的值。
func normalizeQuery(rawQuery string, queryIndex int) (string, error) {
	items := strings.Split(rawQuery, "&")
	if queryIndex < 1 || queryIndex > len(items) {
		return "", fmt.Errorf("vulndedup: query index %d out of range (%d items)", queryIndex, len(items))
	}
	for i, item := range items {
		name, value, hasEq := splitQueryItem(item)
		name = normalizeEscapes(name)
		if i+1 == queryIndex {
			if hasEq {
				items[i] = name + "="
			} else {
				items[i] = name
			}
			continue
		}
		if hasEq {
			items[i] = name + "=" + normalizeEscapes(value)
		} else {
			items[i] = name
		}
	}
	return strings.Join(items, "&"), nil
}

// splitQueryItem 按第一个字面量 "=" 把查询项分为名字和值。
func splitQueryItem(item string) (name, value string, hasEq bool) {
	if i := strings.IndexByte(item, '='); i >= 0 {
		return item[:i], item[i+1:], true
	}
	return item, "", false
}

// normalizeEscapes 只解码 ASCII 字母数字及 -._~ 的百分号转义，
// 其余合法转义统一十六进制字母为大写，不做递归解码。
func normalizeEscapes(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			v := unhex(s[i+1])<<4 | unhex(s[i+2])
			if isUnreserved(v) {
				b.WriteByte(v)
			} else {
				b.WriteByte('%')
				b.WriteByte(toUpperHex(s[i+1]))
				b.WriteByte(toUpperHex(s[i+2]))
			}
			i += 2
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func toUpperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}
