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
	"strings"

	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

func (c *Client) UserIDByName(ctx context.Context, username string) (string, error) {
	rows, err := c.List(ctx, jmsapi.ResUsers)
	if err != nil {
		return "", err
	}
	for _, u := range rows {
		if strings.EqualFold(convert.AnyToStr(u["username"]), username) {
			return convert.AnyToStr(u["id"]), nil
		}
	}
	names := slicex.Map(rows, func(u map[string]any) string {
		return convert.AnyToStr(u["username"])
	})
	return "", fmt.Errorf("no such user: %s (have: %s)", username, strings.Join(names, ", "))
}

func (c *Client) AccessSources(ctx context.Context, UserID string) (map[string][]string, error) {
	perms, err := c.List(ctx, jmsapi.ResPermissions)
	if err != nil {
		return nil, err
	}
	// 部署没有用户组 ⇒ 组授权不可能存在 ⇒ 整段 group 检查短路（一次组列表
	// 请求换掉逐权限×2 的详情拉取；无组部署上全部省掉——issue #8）。组列表
	// 拉不到时不短路（未知 ≠ 没有，落到逐权限详情，行为同旧）。
	groups, gerr := c.List(ctx, jmsapi.ResGroups)
	hasGroups := gerr == nil && len(groups) > 0
	out := map[string][]string{}
	for _, p := range perms {
		var detail map[string]any
		if err := c.Do(ctx, "GET", string(jmsapi.ResPermissions)+convert.AnyToStr(p["id"])+"/", nil, nil, &detail); err != nil {
			continue
		}
		// Does this permission hold the user, directly or through a group?
		holds := false
		for _, u := range jmsapi.AsSlice(detail["users"]) {
			if m, ok := u.(map[string]any); ok && convert.AnyToStr(m["id"]) == UserID {
				holds = true
			}
		}
		if !holds && hasGroups {
			for _, g := range jmsapi.AsSlice(detail["user_groups"]) {
				gm, ok := g.(map[string]any)
				if !ok {
					continue
				}
				// The group's DETAIL carries its members — as bare ids
				// (PrimaryKeyRelatedField) on the versions in the field.
				// Listing "/users/groups/<id>/" instead hit the DETAIL
				// route with a LIST reader, which ShapeError'd and made
				// every group-held permission silently invisible.
				var gdetail map[string]any
				if err := c.Do(ctx, "GET", string(jmsapi.ResGroups)+convert.AnyToStr(gm["id"])+"/", nil, nil, &gdetail); err != nil {
					continue
				}
				for _, u := range jmsapi.AsSlice(gdetail["users"]) {
					if convert.AnyToStr(u) == UserID {
						holds = true
						break
					}
					if m, ok := u.(map[string]any); ok && convert.AnyToStr(m["id"]) == UserID {
						holds = true
						break
					}
				}
			}
		}
		if !holds {
			continue
		}
		name := convert.AnyToStr(detail["name"])
		effective, err := c.EffectiveAssets(ctx, detail)
		if err != nil {
			continue
		}
		for _, a := range effective {
			key := convert.AnyToStr(a["name"])
			out[key] = append(out[key], name)
		}
	}
	return out, nil
}

func (c *Client) UserID(ctx context.Context, username string) (string, error) {
	rows, err := c.List(ctx, jmsapi.ResUsers)
	if err != nil {
		return "", err
	}
	var names []string
	for _, m := range rows {
		u := convert.AnyToStr(m["username"])
		names = append(names, u)
		if strings.EqualFold(u, username) {
			return convert.AnyToStr(m["id"]), nil
		}
	}
	return "", fmt.Errorf("no user %q (have: %s)", username, strings.Join(names, ", "))
}
