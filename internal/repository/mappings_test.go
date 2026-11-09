// mappings_test.go pins the three repository mappings against a fake
// bastion: the row → record projections and the wire shapes they are
// measured against. These moved onto the gateway shapes in 0.12.0 with
// nothing but the compiler and a manual live call behind them — exactly the
// kind of seam that drifts on some later casual edit (a renamed query
// parameter, a timestamp read off the wrong field), discovered only after it
// has pierced the tool layer and become "the tool answers wrong".
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

// newRepoClient mounts a repository.Client over a fake bastion answering
// with fixed JSON. Requests are recorded (method + path + query) for the
// wire-shape assertions; every handler below asserts on them.
func newRepoClient(t *testing.T, routes map[string]string, seen *[]*http.Request) *Client {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range routes {
		b := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			*seen = append(*seen, r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(b))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := &Client{Client: jmsapi.New(jmsapi.Options{
		BaseURL: srv.URL,
		Token:   "test-token",
		// No limiter in tests: the default bucket would pace a 20-row
		// fixture walk into seconds of pointless waiting.
	})}
	return c
}

// FetchCommands maps rows into CommandRecord against the nested asset shape
// the endpoint serves (asset as an object with name/address, risk_level as a
// label object, timestamp as epoch float, timestamp_display as the server's
// rendered string).
func TestFetchCommandsMapping(t *testing.T) {
	var seen []*http.Request
	rows := []map[string]any{
		{
			"id": "cmd-1", "session": "s1", "user": "alice", "account": "root",
			"asset": map[string]any{"name": "web-1", "address": "10.0.0.1"},
			"input": "ls -la", "output": "total 0", "remote_addr": "192.168.1.9",
			// labelled-choice field: the API compares on VALUE, Label()
			// reads the value side of {"value":...,"label":...}.
			"risk_level":        map[string]any{"value": "danger", "label": "危险"},
			"timestamp":         1762400000.5,
			"timestamp_display": "2026-11-06 10:00:00",
		},
		{"id": "cmd-2", "session": "s1", "input": "whoami"},
	}
	raw, _ := json.Marshal(rows)
	c := newRepoClient(t, map[string]string{
		"/api/v1/terminal/commands/": string(raw),
	}, &seen)

	q := url.Values{"date_from": {"2026-11-06"}}
	recs, err := c.FetchCommands(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("2 rows in, got %d records", len(recs))
	}
	r := recs[0]
	if r.ID != "cmd-1" || r.Session != "s1" || r.User != "alice" || r.Account != "root" {
		t.Errorf("flat fields drifted: %+v", r)
	}
	if r.Asset != "web-1" || r.Address != "10.0.0.1" {
		t.Errorf("nested asset fields drifted: got asset=%q address=%q", r.Asset, r.Address)
	}
	if r.RiskLevel != "danger" {
		t.Errorf("risk label drifted: got %q", r.RiskLevel)
	}
	if r.Timestamp != 1762400000.5 || r.When != "2026-11-06 10:00:00" {
		t.Errorf("timestamp drifted: got %v / %q", r.Timestamp, r.When)
	}
	// A row with only the id fields must not panic the projection.
	// NB: absent fields map to "" — pkg#295 (absorbed this round) made
	// convert.AnyToStr(null) null-safe, and the fmt.Sprint reads were
	// unified onto jmsapi.Str, so the whole row is now uniformly empty
	// instead of "User:" " + Asset:"<nil>". This test USED to pin the
	// "<nil>" rendering on purpose ("a later fix to the nil handling
	// shows up here as a deliberate change") — that fix arrived, and
	// this is the deliberate change it asked for.
	if recs[1].User != "" || recs[1].Asset != "" || recs[1].Address != "" || recs[1].RiskLevel != "" {
		t.Errorf("sparse-row mapping drifted: %+v", recs[1])
	}
	// The query must travel as a query string on the gateway shape.
	if len(seen) != 1 || seen[0].URL.Query().Get("date_from") != "2026-11-06" {
		t.Errorf("query not forwarded: %v", seen[0].URL.String())
	}
}

// LabelBoundIDs reads the bound=1 sub-resource view and filters the ids out
// of the rows; the wire shape (path AND query) is the seam this pins.
func TestLabelBoundIDsMapping(t *testing.T) {
	var seen []*http.Request
	rows := []map[string]any{
		{"id": "a1", "hostname": "web-1"},
		{"id": "a2"},
		{"hostname": "no-id-row"},
	}
	raw, _ := json.Marshal(rows)
	c := newRepoClient(t, map[string]string{
		"/api/v1/labels/labels/L1/resource-types/3/resources/": string(raw),
	}, &seen)

	ids, err := c.LabelBoundIDs(context.Background(), "L1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "a1" || ids[1] != "a2" {
		t.Fatalf("id filter drifted: %v", ids)
	}
	q := seen[0].URL.Query()
	if seen[0].URL.Path != "/api/v1/labels/labels/L1/resource-types/3/resources/" {
		t.Errorf("path drifted: %s", seen[0].URL.Path)
	}
	// The bound=1 view survives; the page_size the caller passes does NOT —
	// the walk sets its own limit/page_size (the bastion clamps pages, and
	// the walk must own the paging to terminate correctly). NB: the
	// function comment still says page_size=500; the wire truth is here.
	if q.Get("bound") != "1" || q.Get("limit") == "" || q.Get("page_size") == "" {
		t.Errorf("bound view query drifted: %v", q)
	}
	if q.Get("page_size") == "500" {
		t.Errorf("caller page_size leaked through (walk must own paging): %v", q)
	}
}

// AssetsUnderNode is the passthrough case: the gateway sub-resource shape on
// the wire, the rows returned untouched.
func TestAssetsUnderNodePassthrough(t *testing.T) {
	var seen []*http.Request
	rows := []map[string]any{
		{"id": "a1", "hostname": "web-1"},
		{"id": "a2", "hostname": "db-1"},
	}
	raw, _ := json.Marshal(rows)
	c := newRepoClient(t, map[string]string{
		"/api/v1/assets/nodes/N9/assets/": string(raw),
	}, &seen)

	got, err := c.AssetsUnderNode(context.Background(), "N9")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || fmt.Sprint(got[0]["id"]) != "a1" || fmt.Sprint(got[1]["hostname"]) != "db-1" {
		t.Fatalf("passthrough drifted: %v", got)
	}
	if seen[0].URL.Path != "/api/v1/assets/nodes/N9/assets/" {
		t.Errorf("sub-resource path drifted: %s", seen[0].URL.Path)
	}
}
