// Part of the management plane's repository over the JumpServer API.
//
// jms_status reports four counts about the asset collection. This file is
// the ladder that produces them by the cheapest source the bastion offers,
// because jms_status is the tool an agent reads FIRST — dragging the whole
// asset list over the wire on every call is the costliest possible way to
// answer "how big is this fleet" (issue #7).
//
//	aggregate endpoint  →  one small request, done
//	otherwise           →  the counted walk (the pre-issue behaviour)
package repository

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

// resAssetAmount is the asset-count AGGREGATION endpoint the issue cites
// (the v3-era route). ⚠️ The v4/v5 trees register no such route — only the
// per-node /assets/nodes/assets-amount/ — so on the deployments in the
// field the probe below 404s and the ladder falls through to the walk. The
// probe costs exactly one request for that: a 404 is classified not_found
// and is not retried.
//
// It has no gateway resource shape, which is why the raw Do is the form
// used here: raw paths are the sanctioned route for endpoints without one
// (see Client's doc comment).
const resAssetAmount = "/assets/assets_amount/"

// AssetStats is what the status tool reports about the asset collection.
//
// A count the source did not provide stays nil: a number that was never
// LEARNED must not be published as zero — zero is a measurement and nil is
// an absence, and only one of them is honest.
type AssetStats struct {
	Total           int
	ByPlatform      map[string]int32
	ConnectivityOK  *int32
	ConnectivityErr *int32
}

// AssetStats counts the assets by the cheapest source available.
//
// The total is the SERVER's own count on every rung of the ladder; the
// distribution comes from the aggregate when it carries one, from the rows
// otherwise. Connectivity is known only from rows — no aggregate endpoint
// reports it — so on the light path the two fields stay nil rather than
// pretending the bastion answered.
func (c *Client) AssetStats(ctx context.Context) (*AssetStats, error) {
	if s, ok := c.assetStatsAggregate(ctx); ok {
		return s, nil
	}
	return c.assetStatsByRows(ctx)
}

// assetStatsAggregate probes the aggregation endpoint once.
//
// The shape it accepts is deliberately narrow — an OBJECT carrying a
// numeric `total` and an object-valued `platform` whose every value is a
// number (the shape the issue documents; nothing else is assumed). A body
// that deviates in ANY way reads as "no aggregate" and the ladder falls to
// the walk: a guessed field that does not hold must degrade, never leak
// into the answer.
//
// The distribution is REQUIRED to take the light path. BastionStatus's
// asset_by_platform is a required map, and a total published next to an
// empty distribution reads as "N assets, none on any platform" — a claim
// the caller cannot distinguish from a real one. A total without a
// distribution is not enough, so it is not taken.
func (c *Client) assetStatsAggregate(ctx context.Context) (*AssetStats, bool) {
	var raw json.RawMessage
	if err := c.Do(ctx, "GET", resAssetAmount, nil, nil, &raw); err != nil {
		return nil, false
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return nil, false
	}
	total, ok := countOf(body["total"])
	if !ok {
		return nil, false
	}
	plat, ok := countsOf(body["platform"])
	if !ok {
		return nil, false
	}
	return &AssetStats{Total: total, ByPlatform: plat}, true
}

// assetStatsByRows is the ladder's last rung: the counted walk over the
// assets collection. It is the pre-issue behaviour, kept verbatim —
// including the page shape and the "server's count wins" rule.
//
// ⚠️ This is also the rung that pays for the deployments WITHOUT an
// aggregate (v4/v5 in the field): every jms_status call moves the whole
// asset list over the wire and parses every row, to report four numbers.
// On a 500-asset estate that is the full JSON per call, from every agent
// session that opens with a status check. The aggregate endpoint removes
// it where one exists; where none does, the cost is real and is why the
// tool's answer leaves connectivity unset on the light path — the walk is
// the only source that knows it.
func (c *Client) assetStatsByRows(ctx context.Context) (*AssetStats, error) {
	rows, serverTotal, err := c.ListCounted(ctx, jmsapi.ResAssets, url.Values{"page_size": {"500"}})
	if err != nil {
		return nil, err
	}
	byPlatform := map[string]int32{}
	okCount, errCount := int32(0), int32(0)
	for _, a := range rows {
		p := jmsapi.Str(jmsapi.Nested(a, "platform", "name"))
		if p == "" {
			p = "(none)"
		}
		byPlatform[p]++
		switch jmsapi.Label(a, "connectivity") {
		case "ok":
			okCount++
		case "err":
			errCount++
		}
	}
	// The walk stops when a page comes back shorter than the page it asked
	// for, which is only a correct stop when the server honoured the size —
	// so the SERVER's own count outranks the rows actually read, and rows
	// are the fallback when the envelope carries no count at all (the shape
	// a wrapping-disabled deployment answers with).
	total := len(rows)
	if serverTotal > 0 {
		total = serverTotal
	}
	return &AssetStats{
		Total:           total,
		ByPlatform:      byPlatform,
		ConnectivityOK:  &okCount,
		ConnectivityErr: &errCount,
	}, nil
}

// countOf reads a JSON number, and only a number: a total that arrives as a
// string ("49") is a shape this file does not understand, not a count.
func countOf(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	}
	return 0, false
}

// countsOf reads an object whose every value is a number — the aggregate's
// platform distribution. One value that is not a number poisons the whole
// map: a distribution with a hole in it would silently disagree with the
// total published beside it.
func countsOf(v any) (map[string]int32, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]int32, len(m))
	for k, n := range m {
		c, ok := countOf(n)
		if !ok {
			return nil, false
		}
		out[k] = int32(c)
	}
	return out, true
}
