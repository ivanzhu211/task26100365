# vulndedup

漏洞发现归并库，由上层扫描器调用。数据保存在进程内，支持分批提交发现和读取归并结果。仅处理 GET 查询参数漏洞。

## 用法

```go
s := vulndedup.NewStore()

// 可分批提交；批次划分和提交顺序不影响最终分组。
err := s.Submit([]vulndedup.Finding{
    {ID: "f1", Target: "target-1", CWE: "CWE-79",
     RawURL: "http://EXAMPLE.test:80/a/%2e%2e/b?q=one&x=%7e", QueryIndex: 1},
    {ID: "f2", Target: "target-1", CWE: "CWE-79",
     RawURL: "http://example.test/b?q=two&x=~#proof", QueryIndex: 1},
})
// err 为 nil；以上两条归并为一组。

for _, g := range s.Groups() {
    // g.Key 为归并键；g.Members 保留每条发现的原始 URL，可用于复现。
}
```

同一编号重复提交返回 `ErrDuplicateID`，且该批次不产生任何修改。

## 归并规则

目标标识、CWE、被测项序号以及排除被测值后的规范化 URL 全部相同，才属于同一漏洞。URL 规范化：

- 协议与主机名小写，域名末尾圆点保留；端口按数值比较，省略默认端口；忽略片段，空路径视为根路径。
- 百分号转义只解码 ASCII 字母数字及 `-._~`，其余转义仅统一十六进制字母为大写，不递归解码；转义斜杠不等于字面量斜杠。
- 解码后的点路径段按 RFC 3986 消除，不能越过根目录；路径大小写、连续斜杠和普通结尾斜杠均有意义。
- 查询串只按字面量 `&` 分项、按第一个字面量 `=` 分名字和值；顺序、重复项、空项、等号有无全部保留；`+` 不表示空格。
- 仅忽略被测查询项的值，其名字和等号有无仍参与比较；同名参数的不同出现位置不能归并。

## 测试

```sh
go test ./...
```
