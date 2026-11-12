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

func (c *Client) ResolveNodePaths(ctx context.Context, paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	rows, err := c.List(ctx, jmsapi.ResNodes)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, want := range paths {
		found := ""
		for _, n := range rows {
			full := convert.AnyToStr(n["full_value"])
			if strings.EqualFold(full, want) || strings.HasSuffix(full, "/"+strings.TrimLeft(want, "/")) {
				found = convert.AnyToStr(n["id"])
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("no such node: %s", want)
		}
		ids = append(ids, found)
	}
	return ids, nil
}

type NodeTree struct {
	ByID  map[string]map[string]any
	ByKey map[string]map[string]any
	Order []string
}

func (c *Client) LoadNodeTree(ctx context.Context) (*NodeTree, error) {
	rows, err := c.List(ctx, jmsapi.ResNodes)
	if err != nil {
		return nil, err
	}
	t := &NodeTree{
		ByID:  map[string]map[string]any{},
		ByKey: map[string]map[string]any{},
	}
	for _, n := range rows {
		id := convert.AnyToStr(n["id"])
		t.ByID[id] = n
		t.ByKey[convert.AnyToStr(n["key"])] = n
		t.Order = append(t.Order, id)
	}
	return t, nil
}

func (c *Client) AssetsUnderNode(ctx context.Context, nodeID string) ([]map[string]any, error) {
	// The gateway shape, not a path built here: listing speaks resources
	// even in this layer — raw paths are for endpoints with no gateway shape.
	return c.ListSub(ctx, jmsapi.ResNodes, nodeID, "assets")
}

// Descendants lists the node itself and everything filed below it.
//
// A nil tree is an empty tree, not a panic: the tree is loaded from the API,
// and a caller that could not load it still has to be able to ask the
// question.
func (t *NodeTree) Descendants(nodeID string) []string {
	if t == nil {
		return []string{nodeID}
	}
	n, ok := t.ByID[nodeID]
	if !ok {
		return []string{nodeID}
	}
	key := convert.AnyToStr(n["key"])
	out := []string{nodeID}
	for id, other := range t.ByID {
		ok := convert.AnyToStr(other["key"])
		if ok != key && strings.HasPrefix(ok, key+":") {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}
