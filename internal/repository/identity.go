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
	// The group branch below fires once per group per permission and each
	// round is its own detail request — an N+1 the deployment can rule out in
	// ONE list call. A deployment with no user groups can never take the
	// branch: group-held authorization cannot exist where no group does, so
	// the whole branch is skipped for the entire loop (issue #8). This is the
	// same list jms_user_groups_list reads.
	//
	// ⚠️ A FAILED group list is not "no groups": reading an UNANSWERED
	// question as "empty" would silently drop every group-held grant from the
	// attribution. A failed fetch leaves the branch exactly as it was.
	noGroups := false
	if groups, gerr := c.List(ctx, jmsapi.ResGroups); gerr == nil {
		noGroups = len(groups) == 0
	}
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
		if !holds && !noGroups {
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
