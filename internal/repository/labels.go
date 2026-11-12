// Part of the management plane's repository over the JumpServer API.
//
// The transport and the parsing of the two response shapes v5 mixes live in
// jms-kit/pkg/jmsapi; what is here is the questions the tools ask and the
// resources they get back.
package repository

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"

	"github.com/oekit/pkg/convert"
)

func (c *Client) LabelLookup(ctx context.Context, name, value string) (string, string, error) {
	q := url.Values{"name": {name}}
	if value != "" {
		q.Set("value", value)
	}
	rows, err := c.ListQuery(ctx, jmsapi.ResLabels, q)
	if err != nil {
		return "", "", err
	}
	var names []string
	for _, m := range rows {
		n := convert.AnyToStr(m["name"])
		names = append(names, n)
		if strings.EqualFold(n, name) && (value == "" || convert.AnyToStr(m["value"]) == value) {
			return convert.AnyToStr(m["id"]), convert.AnyToStr(m["value"]), nil
		}
	}
	if len(names) > 0 {
		return "", "", fmt.Errorf("no label %q with value %q; this key exists with: %s",
			name, value, strings.Join(names, ", "))
	}
	return "", "", fmt.Errorf("no label %q; list them with jms_labels_list", name)
}

func (c *Client) RoleLookup(ctx context.Context, ref string) (string, error) {
	if IsUUID(ref) {
		return ref, nil
	}
	rows, err := c.ListQuery(ctx, jmsapi.ResOrgRoles, url.Values{"name": {ref}})
	if err != nil {
		return "", err
	}
	var names []string
	for _, m := range rows {
		n := convert.AnyToStr(m["name"])
		names = append(names, n)
		if strings.EqualFold(n, ref) {
			return convert.AnyToStr(m["id"]), nil
		}
	}
	return "", fmt.Errorf("no role %q; available: %s", ref, strings.Join(names, ", "))
}

func (c *Client) ContentTypeID(ctx context.Context, model string) (int, error) {
	rows, err := c.List(ctx, jmsapi.ResContentTypes)
	if err != nil {
		return 0, err
	}
	var models []string
	for _, m := range rows {
		mo := convert.AnyToStr(m["model"])
		models = append(models, mo)
		if strings.EqualFold(mo, model) {
			if id, ok := m["id"].(float64); ok {
				return int(id), nil
			}
		}
	}
	slices.Sort(models)
	return 0, fmt.Errorf("unknown content type %q; known models include: %s",
		model, strings.Join(models, ", "))
}

func (c *Client) LabelAttach(ctx context.Context, labelID string, ctID int, add, remove []string) (string, error) {
	cur, err := c.LabelBoundIDs(ctx, labelID, ctID)
	if err != nil {
		return "", err
	}
	before := len(cur)
	desired := map[string]bool{}
	for _, id := range cur {
		desired[id] = true
	}
	for _, id := range add {
		desired[id] = true
	}
	for _, id := range remove {
		delete(desired, id)
	}
	want := slices.Collect(maps.Keys(desired))
	slices.Sort(want)

	// The gateway's Put shape, not a path built here: the sub-resource PUT
	// has a gateway form (Put(res, id, sub, ...) — the same shape Put has
	// served for a user's password and a node's assets), and this endpoint
	// fits it exactly. The raw-path Do this used to be was the write-side
	// leak the listing side had already been closed on.
	body := map[string]any{"res_ids": want}
	var out map[string]any
	if err := c.Put(ctx, jmsapi.ResLabels, labelID,
		fmt.Sprintf("resource-types/%d/resources", ctID), body, &out); err != nil {
		return "", fmt.Errorf("attach failed: %w", err)
	}
	return fmt.Sprintf("%d resource(s) now carry the label (was %d)", len(want), before), nil
}

// LabelBoundIDs reads the ids of the resources a label is bound to.
//
// It is the "bound=1" view: the resources that actually carry the label,
// as opposed to every resource of that content type.
func (c *Client) LabelBoundIDs(ctx context.Context, labelID string, ctID int) ([]string, error) {
	// The "bound=1" view as a query on the gateway's sub-resource shape —
	// not a query string concatenated onto a path built here. The page_size
	// here is a wish, not a promise: the walk owns the paging (it sets its
	// own limit/page_size so it terminates on a clamped page) — pinned in
	// mappings_test.go.
	rows, err := c.ListSubQuery(ctx, jmsapi.ResLabels, labelID,
		fmt.Sprintf("resource-types/%d/resources", ctID),
		url.Values{"bound": {"1"}, "page_size": {"500"}})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, m := range rows {
		if id, ok := m["id"]; ok && id != nil {
			out = append(out, convert.AnyToStr(id))
		}
	}
	return out, nil
}
