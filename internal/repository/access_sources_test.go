package repository_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// AccessSources attributes each reachable asset to the permissions that
// grant it. The grants a user holds THROUGH A GROUP used to cost one group
// detail request per group per permission; the tests here pin the
// deployment-level short-circuit (issue #8): a deployment with NO user
// groups can never take the group branch, so it must not fire — while a
// failed group list must NOT be read as "no groups", because reading an
// unanswered question as empty silently drops every group-held grant.

// accessSourcesFake answers the two shapes AccessSources reads.
//
// hits records every request path; the tests assert on it, so a
// short-circuit that never fires cannot pass unnoticed.
type accessSourcesFake struct {
	groupDetailHits int // GET /users/groups/g-1/ — the group branch's round trip
	groupListHits   int // GET /users/groups/    — the one-call pre-read
}

func accessSourcesBastion(t *testing.T, groupsJSON, groupDetail string) (*httptest.Server, *accessSourcesFake) {
	t.Helper()
	fake := &accessSourcesFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/perms/asset-permissions/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The collection answers with the ids only; the detail carries the
		// membership and the named assets (as objects, so EffectiveAssets
		// reads them without walking the node tree).
		switch r.URL.Path {
		case "/api/v1/perms/asset-permissions/":
			json.NewEncoder(w).Encode([]map[string]any{{"id": "p1"}, {"id": "p2"}})
		case "/api/v1/perms/asset-permissions/p1/":
			// The user is named DIRECTLY; no group is involved.
			json.NewEncoder(w).Encode(map[string]any{
				"id": "p1", "name": "direct-grant",
				"users":       []map[string]any{{"id": "u-9"}},
				"user_groups": []any{},
				"assets":      []map[string]any{{"id": "a-1", "name": "web-1"}},
			})
		case "/api/v1/perms/asset-permissions/p2/":
			// The user is only reachable THROUGH the group — this is the
			// branch the empty-deployment short-circuit skips.
			json.NewEncoder(w).Encode(map[string]any{
				"id": "p2", "name": "group-grant",
				"users":       []any{},
				"user_groups": []map[string]any{{"id": "g-1"}},
				"assets":      []map[string]any{{"id": "a-2", "name": "db-1"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"not found"}`))
		}
	})
	// EffectiveAssets loads the node tree before reading the permission's
	// named assets; an empty tree keeps the fixture on the assets alone.
	mux.HandleFunc("/api/v1/assets/nodes/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/v1/users/groups/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fake.groupListHits++
		if groupsJSON == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"detail":"no users.view_usergroup"}`))
			return
		}
		w.Write([]byte(groupsJSON))
	})
	mux.HandleFunc("/api/v1/users/groups/g-1/", func(w http.ResponseWriter, r *http.Request) {
		fake.groupDetailHits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(groupDetail))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, fake
}

// A deployment with no user groups: the group branch must not fire, not even
// once — the group's detail request is the N+1 the short-circuit exists to
// remove, and the group-held permission must NOT be attributed (its grant
// cannot exist where no group does).
func TestAccessSourcesSkipsGroupBranchWhenDeploymentHasNoGroups(t *testing.T) {
	// g-1's detail WOULD answer with the user as a member — if the branch
	// fired, db-1 would be attributed and the test would fail on the hit
	// count, not just on the attribution. A fixture that only proves the
	// attribution wrong lets a still-running branch pass half-checked.
	ts, fake := accessSourcesBastion(t, `[]`, `{"id": "g-1", "users": ["u-9"]}`)
	c := repository.NewBase(ts.URL, "test-token", ts.Client())

	out, err := c.AccessSources(context.Background(), "u-9")
	if err != nil {
		t.Fatalf("AccessSources: %v", err)
	}
	if got := out["web-1"]; len(got) != 1 || got[0] != "direct-grant" {
		t.Errorf("web-1 = %v, want [direct-grant]", got)
	}
	if _, ok := out["db-1"]; ok {
		t.Errorf("db-1 attributed %v: a group-held grant cannot exist on a "+
			"deployment with no groups", out["db-1"])
	}
	if fake.groupListHits == 0 {
		t.Errorf("the group list was never fetched — the short-circuit decided with no input")
	}
	if fake.groupDetailHits != 0 {
		t.Errorf("the group detail fired %d times on a no-group deployment: "+
			"the short-circuit did not take", fake.groupDetailHits)
	}
}

// With groups present the branch keeps working: membership through a group
// still attributes the asset (the group detail carries its members as bare
// ids — the shape the branch exists to read).
func TestAccessSourcesStillFollowsGroupsWhenTheyExist(t *testing.T) {
	ts, fake := accessSourcesBastion(t, `[{"id": "g-1"}]`, `{"id": "g-1", "users": ["u-9"]}`)
	c := repository.NewBase(ts.URL, "test-token", ts.Client())

	out, err := c.AccessSources(context.Background(), "u-9")
	if err != nil {
		t.Fatalf("AccessSources: %v", err)
	}
	if got := out["db-1"]; len(got) != 1 || got[0] != "group-grant" {
		t.Errorf("db-1 = %v, want [group-grant]: a group the user is in still grants", got)
	}
	if fake.groupDetailHits == 0 {
		t.Errorf("the group detail was never fetched although a permission held the group")
	}
}

// A group list that FAILS is not an empty one: 403 on /users/groups/ (a
// credential without users.view_usergroup) must leave the group branch in
// place, or every group-held grant would silently vanish from the
// attribution — the exact misread the short-circuit must not introduce.
func TestAccessSourcesKeepsGroupBranchWhenTheListFails(t *testing.T) {
	ts, fake := accessSourcesBastion(t, "", `{"id": "g-1", "users": ["u-9"]}`)
	c := repository.NewBase(ts.URL, "test-token", ts.Client())

	out, err := c.AccessSources(context.Background(), "u-9")
	if err != nil {
		t.Fatalf("AccessSources: %v", err)
	}
	if got := out["db-1"]; len(got) != 1 || got[0] != "group-grant" {
		t.Errorf("db-1 = %v, want [group-grant]: a FAILED group list is not "+
			"\"no groups\" — the branch must stay", got)
	}
	if fake.groupDetailHits == 0 {
		t.Errorf("the group detail was never fetched although the group list "+
			"was unreadable (403) — the branch was skipped on an unanswered question")
	}
}
