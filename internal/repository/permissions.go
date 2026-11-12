// Part of the management plane's repository over the JumpServer API.
//
// The transport and the parsing of the two response shapes v5 mixes live in
// jms-kit/pkg/jmsapi; what is here is the questions the tools ask and the
// resources they get back.
package repository

import (
	"context"
	"fmt"
	"github.com/oekit/pkg/slicex"
	"maps"
	"slices"
	"strings"

	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

func (c *Client) PermissionIDByName(ctx context.Context, ref string) (string, error) {
	if IsUUID(ref) {
		return ref, nil
	}
	rows, err := c.List(ctx, jmsapi.ResPermissions)
	if err != nil {
		return "", err
	}
	for _, p := range rows {
		if strings.EqualFold(convert.AnyToStr(p["name"]), ref) {
			return convert.AnyToStr(p["id"]), nil
		}
	}
	for _, p := range rows {
		if strings.Contains(strings.ToLower(convert.AnyToStr(p["name"])), strings.ToLower(ref)) {
			return convert.AnyToStr(p["id"]), nil
		}
	}
	names := slicex.Map(rows, func(p map[string]any) string {
		return convert.AnyToStr(p["name"])
	})
	return "", fmt.Errorf("no such permission: %s (have: %s)", ref, strings.Join(names, ", "))
}

func (c *Client) PermissionDetail(ctx context.Context, ref string) (map[string]any, error) {
	id, err := c.PermissionIDByName(ctx, ref)
	if err != nil {
		return nil, err
	}
	var detail map[string]any
	if err := c.Do(ctx, "GET", string(jmsapi.ResPermissions)+id+"/", nil, nil, &detail); err != nil {
		return nil, err
	}
	return detail, nil
}

func (c *Client) EffectiveAssets(ctx context.Context, perm map[string]any) ([]map[string]any, error) {
	tree, err := c.LoadNodeTree(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]map[string]any{}
	for _, a := range jmsapi.AsSlice(perm["assets"]) {
		if m, ok := a.(map[string]any); ok {
			seen[convert.AnyToStr(m["id"])] = m
		}
	}
	for _, nref := range jmsapi.AsSlice(perm["nodes"]) {
		nm, ok := nref.(map[string]any)
		if !ok {
			continue
		}
		for _, nid := range tree.Descendants(convert.AnyToStr(nm["id"])) {
			rows, err := c.AssetsUnderNode(ctx, nid)
			if err != nil {
				continue
			}
			for _, a := range rows {
				seen[convert.AnyToStr(a["id"])] = a
			}
		}
	}
	out := slices.Collect(maps.Values(seen))
	slices.SortFunc(out, func(a, b map[string]any) int {
		return strings.Compare(convert.AnyToStr(a["name"]), convert.AnyToStr(b["name"]))
	})
	return out, nil
}
