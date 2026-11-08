package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/testsupport"

	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
	"github.com/yi-nology/jumpserver-mgmt/internal/service/policy"
)

// jms_status reports four asset counts, and it is the tool an agent session
// OPENS with. The tests pin the counting ladder (issue #7): the aggregate
// endpoint is used when the deployment has one — and then the asset list
// must NOT be dragged over the wire; any other deployment walks the rows
// exactly as before the issue.

// countsBastion answers the identity probe, the aggregate probe and the
// assets list. assetAmountJSON == "" means the aggregate route 404s; a
// non-empty assetListJSON registers the assets route and counts its hits —
// the hit count is how a test proves the list was (or was not) fetched.
type countsBastion struct {
	assetAmountJSON string
	assetListJSON   string
	assetListHits   int
}

func countsBastionServer(t *testing.T, b *countsBastion) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/profile/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "u-probe", "username": "zz_probe", "name": "Probe User", "is_superuser": false,
		})
	})
	mux.HandleFunc("/api/v1/assets/assets_amount/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if b.assetAmountJSON == "" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"not found"}`))
			return
		}
		w.Write([]byte(b.assetAmountJSON))
	})
	if b.assetListJSON != "" {
		mux.HandleFunc("/api/v1/assets/assets/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			b.assetListHits++
			w.Write([]byte(b.assetListJSON))
		})
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func countsStatusCall(t *testing.T, b *countsBastion) map[string]any {
	t.Helper()
	ts := countsBastionServer(t, b)
	c := repository.NewBase(ts.URL, "test-token", ts.Client())
	cs := testsupport.NewSession(t, "jms-test", reg.Options{Policy: policy.Table},
		func(r *reg.Registry) { RegisterStatusTools(r, c) })
	return testsupport.CallToolJSON(t, cs, "jms_status", map[string]any{})
}

// An aggregate that answers: the total and the distribution come out of ONE
// small request and the asset list is NEVER fetched — that fetch is the
// whole cost the ladder exists to remove. Connectivity stays ABSENT on the
// light path: no aggregate reports it, and an unlearned count must not be
// published as zero.
func TestStatusCountsFromTheAggregateWithoutDraggingTheAssetList(t *testing.T) {
	b := &countsBastion{
		assetAmountJSON: `{"total": 3, "platform": {"Linux": 2, "MySQL": 1}}`,
		assetListJSON:   `[]`, // registered only so a stray fetch is VISIBLE (a hit fails the test)
	}
	out := countsStatusCall(t, b)

	if n, _ := out["asset_total"].(float64); n != 3 {
		t.Errorf("asset_total = %v, want 3 from the aggregate", out["asset_total"])
	}
	plat, _ := out["asset_by_platform"].(map[string]any)
	if len(plat) != 2 || plat["Linux"] != float64(2) || plat["MySQL"] != float64(1) {
		t.Errorf("asset_by_platform = %v, want map[Linux:2 MySQL:1] from the aggregate", out["asset_by_platform"])
	}
	if b.assetListHits != 0 {
		t.Errorf("the asset list was fetched %d times although the aggregate answered: "+
			"the full-asset fetch is the cost this tool exists to avoid", b.assetListHits)
	}
	if v, ok := out["connectivity_ok"]; ok && v != nil {
		t.Errorf("connectivity_ok = %v on the light path: no aggregate reports it, "+
			"an unlearned count must not be published", v)
	}
	if v, ok := out["connectivity_err"]; ok && v != nil {
		t.Errorf("connectivity_err = %v on the light path: no aggregate reports it, "+
			"an unlearned count must not be published", v)
	}
}

// No aggregate (the v4/v5 field shape): the walk answers everything, exactly
// as before the issue — total, distribution, connectivity.
func TestStatusWalksTheRowsWhenThereIsNoAggregate(t *testing.T) {
	b := &countsBastion{assetListJSON: `[
		{"id": "a-1", "platform": {"name": "Linux"}, "connectivity": {"value": "ok"}},
		{"id": "a-2", "platform": {"name": "MySQL"}, "connectivity": {"value": "err"}}
	]`}
	out := countsStatusCall(t, b)

	if n, _ := out["asset_total"].(float64); n != 2 {
		t.Errorf("asset_total = %v, want 2 from the walked rows", out["asset_total"])
	}
	plat, _ := out["asset_by_platform"].(map[string]any)
	if len(plat) != 2 || plat["Linux"] != float64(1) || plat["MySQL"] != float64(1) {
		t.Errorf("asset_by_platform = %v, want map[Linux:1 MySQL:1] from the rows", out["asset_by_platform"])
	}
	if n, _ := out["connectivity_ok"].(float64); n != 1 {
		t.Errorf("connectivity_ok = %v, want 1 from the rows", out["connectivity_ok"])
	}
	if n, _ := out["connectivity_err"].(float64); n != 1 {
		t.Errorf("connectivity_err = %v, want 1 from the rows", out["connectivity_err"])
	}
	if b.assetListHits != 1 {
		t.Errorf("the asset list was fetched %d times, want exactly the one page of the walk", b.assetListHits)
	}
}

// An aggregate that answers with a body this file's shape does not
// understand must degrade, not leak into the answer: the walk produces the
// counts instead. A wrong guess that silently degrades is invisible; one
// that corrupts the answer is a lie.
func TestStatusWalksWhenTheAggregateBodyIsUnrecognizable(t *testing.T) {
	b := &countsBastion{
		assetAmountJSON: `{"detail": "this is not an aggregate"}`,
		assetListJSON: `[
			{"id": "a-1", "platform": {"name": "Linux"}, "connectivity": {"value": "ok"}},
			{"id": "a-2", "platform": {"name": "Linux"}, "connectivity": {"value": "ok"}}
		]`,
	}
	out := countsStatusCall(t, b)

	if n, _ := out["asset_total"].(float64); n != 2 {
		t.Errorf("asset_total = %v, want 2 from the walked rows after an unreadable aggregate", out["asset_total"])
	}
	if n, _ := out["connectivity_ok"].(float64); n != 2 {
		t.Errorf("connectivity_ok = %v, want 2: the fallback path carries connectivity too", out["connectivity_ok"])
	}
}

// A total-only aggregate is not enough either: the contract's platform map
// is REQUIRED, and a total published beside an empty distribution reads as
// "N assets, none on any platform". The ladder falls to the walk rather
// than publish that.
func TestStatusWalksWhenTheAggregateCarriesNoDistribution(t *testing.T) {
	b := &countsBastion{
		assetAmountJSON: `{"total": 3}`,
		assetListJSON: `[
			{"id": "a-1", "platform": {"name": "Linux"}, "connectivity": {"value": "ok"}}
		]`,
	}
	out := countsStatusCall(t, b)

	// The WALK's numbers are what goes out — not the aggregate's orphan
	// total beside a lying empty map.
	if n, _ := out["asset_total"].(float64); n != 1 {
		t.Errorf("asset_total = %v, want 1: a distribution-less aggregate is not taken, the walk's answer is", out["asset_total"])
	}
	plat, _ := out["asset_by_platform"].(map[string]any)
	if len(plat) != 1 || plat["Linux"] != float64(1) {
		t.Errorf("asset_by_platform = %v, want map[Linux:1] from the walked rows", out["asset_by_platform"])
	}
}

// The server's own count outranks the rows read, also on the walked path:
// an envelope-carried count wins over the rows in the page (the parity the
// pre-issue walk kept, kept by its new home in repository.AssetStats).
func TestStatusWalkReportsTheServersCountNotThePageRows(t *testing.T) {
	b := &countsBastion{assetListJSON: `{"count": 5, "results": [
		{"id": "a-1", "platform": {"name": "Linux"}, "connectivity": {"value": "ok"}},
		{"id": "a-2", "platform": {"name": "MySQL"}, "connectivity": {"value": "err"}}
	]}`}
	out := countsStatusCall(t, b)

	if n, _ := out["asset_total"].(float64); n != 5 {
		t.Errorf("asset_total = %v, want 5 — the envelope's count, not the %d rows in the page",
			out["asset_total"], b.assetListHits*2)
	}
	if n, _ := out["connectivity_ok"].(float64); n != 1 {
		t.Errorf("connectivity_ok = %v, want 1 — the distribution is over the rows actually read", out["connectivity_ok"])
	}
}
