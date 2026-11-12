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
	"slices"
	"strings"

	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

// ResolveAssets finds the assets the references name.
//
// The matching itself lives in pkg/jmsapi: the execution plane resolves
// assets too (to mint a connection token, whose body carries the asset's
// UUID), and two implementations of "which asset did the caller mean" would
// drift into "this asset exists but the session says there is no such
// asset". What is added here is the shape the management plane's tools
// expect: the ids and the metadata rows.
func (c *Client) ResolveAssets(ctx context.Context, refs []string) ([]string, []map[string]any, error) {
	out, err := c.Client.ResolveAssets(ctx, refs)
	ids := make([]string, 0, len(out))
	meta := make([]map[string]any, 0, len(out))
	for _, r := range out {
		ids = append(ids, r.ID)
		meta = append(meta, map[string]any{
			"id": r.ID, "name": r.Name, "address": r.Address, "platform": r.Platform,
		})
	}
	return ids, meta, err
}

func (c *Client) AssetCreateEndpoint(ctx context.Context, platformID string) (string, error) {
	var p map[string]any
	if err := c.Do(ctx, "GET", string(jmsapi.ResPlatforms)+platformID+"/", nil, nil, &p); err != nil {
		return "", err
	}
	category := jmsapi.Label(p, "category")
	name := convert.AnyToStr(p["name"])

	switch category {
	case "host":
		return string(jmsapi.ResAssetHosts), nil
	case "database":
		return string(jmsapi.ResAssetDatabases), nil
	case "device":
		return string(jmsapi.ResAssetDevices), nil
	case "cloud":
		return string(jmsapi.ResAssetClouds), nil
	case "web":
		return string(jmsapi.ResAssetWebs), nil
	}
	return "", fmt.Errorf("platform %q has category %q, which has no known create endpoint; "+
		"add it through the JumpServer UI or pick a host/database/device platform", name, category)
}

func (c *Client) PlatformIDByName(ctx context.Context, name string) (string, error) {
	rows, err := c.List(ctx, jmsapi.ResPlatforms)
	if err != nil {
		return "", err
	}
	for _, p := range rows {
		if strings.EqualFold(convert.AnyToStr(p["name"]), name) {
			return convert.AnyToStr(p["id"]), nil
		}
	}
	names := slicex.Map(rows, func(p map[string]any) string {
		return convert.AnyToStr(p["name"])
	})
	slices.Sort(names)
	return "", fmt.Errorf("no such platform: %s (known: %s)", name, strings.Join(names, ", "))
}

type AssetSpec struct {
	Name      string
	Address   string
	Platform  string
	Protocols []string
	SSHPort   int
	Nodes     []string
	Comment   string
}

// CreateAsset registers an asset and returns the bastion's own record of it.
//
// The record is handed over raw: the tool layer decides what to say about
// it, and the contract that says it is one word for "an asset" -- the same
// one jms_asset_get answers with.
func (c *Client) CreateAsset(ctx context.Context, spec AssetSpec) (map[string]any, error) {
	if len(spec.Protocols) == 0 {
		return nil, fmt.Errorf("protocols is required in practice: without them the asset can never be connected to")
	}
	platID, err := c.PlatformIDByName(ctx, spec.Platform)
	if err != nil {
		return nil, err
	}
	endpoint, err := c.AssetCreateEndpoint(ctx, platID)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"name": spec.Name, "address": spec.Address,
		"platform": platID, "protocols": BuildProtocols(spec.Protocols, spec.SSHPort),
		"is_active": true,
	}
	if spec.Comment != "" {
		body["comment"] = spec.Comment
	}
	if len(spec.Nodes) > 0 {
		nodeIDs, err := c.ResolveNodePaths(ctx, spec.Nodes)
		if err != nil {
			return nil, err
		}
		body["nodes"] = IDList(nodeIDs)
	}
	var out map[string]any
	if err := c.Do(ctx, "POST", endpoint, nil, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
