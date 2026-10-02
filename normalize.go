package vulnmerge

import (
	"fmt"
	"strconv"
	"strings"
)

// testedValuePlaceholder 替换被测查询项的值，不会出现在规范化后的文本中。
const testedValuePlaceholder = "\x00"

// normalizeURL 对原始 URL 做保守规范化，返回用于身份比较的字符串。
// testedIndex 为被测查询项序号（从 1 开始，包含空查询项）。
// 被测项的值被替换为占位符，其余部分按规则规范化。
func normalizeURL(raw string, testedIndex int) (string, error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", fmt.Errorf("invalid URL: missing scheme: %q", raw)
	}
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported scheme: %q", scheme)
	}

	// 去掉片段。
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}

	// 拆分 authority 与 path/query。
	var authority, pathQuery string
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, pathQuery = rest[:i], rest[i:]
	} else {
		authority = rest
	}

	host, port := splitHostPort(authority)
	host = strings.ToLower(host) // 域名末尾圆点保留，仅统一大小写

	// 端口按数值比较，仅省略对应协议的默认端口。
	portPart := ""
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return "", fmt.Errorf("invalid port in %q", raw)
		}
		if !isDefaultPort(scheme, n) {
			portPart = ":" + strconv.Itoa(n)
		}
	}

	// 拆分路径与查询串。
	var path, query string
	hasQuery := false
	if i := strings.IndexByte(pathQuery, '?'); i >= 0 {
		path, query = pathQuery[:i], pathQuery[i+1:]
		hasQuery = true
	} else {
		path = pathQuery
	}
	if path == "" {
		path = "/" // 空路径视为根路径
	}

	normPath := removeDotSegments(decodeUnreserved(path))
	normQuery, err := normalizeQuery(query, testedIndex)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	b.WriteString(portPart)
	b.WriteString(normPath)
	if hasQuery {
		b.WriteByte('?')
		b.WriteString(normQuery)
	}
	return b.String(), nil
}

// splitHostPort 拆分主机与端口；主机为 ASCII 域名，不含用户信息。
func splitHostPort(authority string) (host, port string) {
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		return authority[:i], authority[i+1:]
	}
	return authority, ""
}

func isDefaultPort(scheme string, port int) bool {
	return scheme == "http" && port == 80 || scheme == "https" && port == 443
}

// isUnreserved 判断字节是否为 RFC3986 unreserved 字符。
func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
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

const upperHex = "0123456789ABCDEF"

// decodeUnreserved 只解码 unreserved 字符的百分号转义；
// 其余转义仅统一十六进制字母为大写，不递归解码。
func decodeUnreserved(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			v := unhex(s[i+1])<<4 | unhex(s[i+2])
			if isUnreserved(v) {
				b.WriteByte(v)
			} else {
				b.WriteByte('%')
				b.WriteByte(upperHex[v>>4])
				b.WriteByte(upperHex[v&0xf])
			}
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// removeDotSegments 按 RFC3986 语义处理解码后的点路径段。
// 单点段表示当前目录，双点段退回一层且不越过根目录；
// 结尾点段代表目录。连续斜杠与结尾斜杠保留。
func removeDotSegments(path string) string {
	segs := strings.Split(path, "/")
	out := make([]string, 0, len(segs))
	for i, seg := range segs {
		last := i == len(segs)-1
		switch seg {
		case ".":
			if last {
				out = append(out, "") // 结尾单点段代表目录
			}
		case "..":
			if len(out) > 1 { // 不越过根目录（out[0] 为根锚点）
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "") // 结尾双点段代表目录
			}
		default:
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/")
}

// normalizeQuery 规范化查询串：只按字面量 '&' 分项，每项按第一个
// 字面量 '=' 分名字和值；顺序、重复项、空项、等号有无全部保留。
// 序号为 testedIndex（1 起，含空项）的项，其值替换为占位符，
// 名字与等号有无仍参与比较。
func normalizeQuery(query string, testedIndex int) (string, error) {
	if testedIndex < 1 {
		return "", fmt.Errorf("tested index must be >= 1, got %d", testedIndex)
	}
	items := strings.Split(query, "&")
	if testedIndex > len(items) {
		return "", fmt.Errorf("tested index %d out of range (%d items)", testedIndex, len(items))
	}
	for i, item := range items {
		name, value, hasEq := strings.Cut(item, "=")
		name = decodeUnreserved(name)
		if i+1 == testedIndex {
			if hasEq {
				items[i] = name + "=" + testedValuePlaceholder
			} else {
				items[i] = name
			}
			continue
		}
		if hasEq {
			items[i] = name + "=" + decodeUnreserved(value)
		} else {
			items[i] = name
		}
	}
	return strings.Join(items, "&"), nil
}
