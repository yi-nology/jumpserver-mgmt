// Part of the management plane's repository over the JumpServer API.
//
// The transport and the parsing of the two response shapes v5 mixes live in
// jms-kit/pkg/jmsapi; what is here is the questions the tools ask and the
// resources they get back.
package repository

import (
	"context"
	"net/url"

	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

type CommandRecord struct {
	ID         string
	Session    string
	User       string
	Asset      string
	Address    string
	Account    string
	RemoteAddr string
	Input      string
	Output     string
	RiskLevel  string
	Timestamp  float64
	When       string
}

func (c *Client) FetchCommands(ctx context.Context, q url.Values) ([]CommandRecord, error) {
	// listAll, not a single page_size request: the endpoint ignores
	// page_size above its own cap of 200 rows, so a one-shot read returns
	// only the newest 200 commands and silently truncates the audit trail.
	// The query goes as a query, not concatenated onto the path: the gateway
	// shape exists (ListQuery), and a caller-written "?a=1" on a path is
	// exactly what the tool-layer guard exists to catch one floor up.
	rows, err := c.ListQuery(ctx, jmsapi.ResTerminalCommands, q)
	if err != nil {
		return nil, err
	}
	out := make([]CommandRecord, 0, len(rows))
	for _, m := range rows {
		ts := convert.AnyToFloat64(m["timestamp"])
		out = append(out, CommandRecord{
			ID:      convert.AnyToStr(m["id"]),
			Session: convert.AnyToStr(m["session"]),
			User:    convert.AnyToStr(m["user"]),
			// Asset/Address 走空安全读（jmsapi.Str）：缺席字段统一映射成
			// 空串——pkg#295 收编后 AnyToStr(nil) 已经是 ""，fmt.Sprint(nil)
			// 的字面 "<nil>" 是同一行上唯一还像值的缺席（两种口径并存比
			// 一种更糟）。
			Asset:      jmsapi.Str(jmsapi.AssetField(m, "name")),
			Address:    jmsapi.Str(jmsapi.AssetField(m, "address")),
			Account:    convert.AnyToStr(m["account"]),
			RemoteAddr: convert.AnyToStr(m["remote_addr"]),
			Input:      convert.AnyToStr(m["input"]),
			Output:     convert.AnyToStr(m["output"]),
			RiskLevel:  jmsapi.Label(m, "risk_level"),
			Timestamp:  ts,
			When:       convert.AnyToStr(m["timestamp_display"]),
		})
	}
	return out, nil
}
