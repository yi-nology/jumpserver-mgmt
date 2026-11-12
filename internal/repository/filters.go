// Part of the management plane's repository over the JumpServer API.
//
// The transport and the parsing of the two response shapes v5 mixes live in
// jms-kit/pkg/jmsapi; what is here is the questions the tools ask and the
// resources they get back.
package repository

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"

	"github.com/oekit/pkg/convert"
)

func (c *Client) CommandGroupID(ctx context.Context, ref string) (string, error) {
	if IsUUID(ref) {
		return ref, nil
	}
	rows, err := c.List(ctx, jmsapi.ResCmdGroups)
	if err != nil {
		return "", err
	}
	names := []string{}
	for _, g := range rows {
		names = append(names, convert.AnyToStr(g["name"]))
		if MatchesRef(g, ref) {
			return convert.AnyToStr(g["id"]), nil
		}
	}
	slices.Sort(names)
	return "", fmt.Errorf("no such command group: %s (have: %s). Create it with jms_cmdgroup_create",
		ref, strings.Join(names, ", "))
}
