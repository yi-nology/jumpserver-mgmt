package handler

// tools_delegation.go exposes JumpServer's official AI credential scheme.
//
// The distinction that matters when reading these tools: delegation is not a way
// to do MORE than the token path. It is a way to do the SAME things under a
// credential that cannot be replayed, cannot be pointed at another endpoint, and
// expires in under a minute. Reach for it when you would not want a leaked
// long-lived token, not when a call fails on the token path.

import (
	"context"
	"encoding/json"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterDelegationTools(r *reg.Registry, c *repository.Client) {
	type statusArgs struct{}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_delegation_status",
		Description:  "Whether the Chat AI delegation credential is configured here, and what each request is bound to. Use it to check the wiring before relying on jms_delegation_call. Delegation is JumpServer's official scheme for AI callers: one credential authorises exactly one call (one method, path, query and body), once, for under a minute. It grants nothing extra — the user still goes through normal RBAC — but a leaked credential is useless elsewhere.",
		OutputSchema: render.Schema[jmsms.DelegationStatus](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ statusArgs) (*mcp.CallToolResult, any, error) {
		// TWO questions, asked separately, because their answers call for
		// different things: does the DEPLOYMENT have the scheme at all, and
		// is it CONFIGURED here.
		// THREE states, not two: the deployment may have the scheme, not
		// have it, or we may not know. ⚠️ "We do not know" must not be
		// reported as "it does not have it" — that would tell an operator
		// to go and configure a scheme that is not there.
		state := c.Profile(ctx).State(jmsapi.CapDelegation)
		hasScheme := state == jmsapi.CapabilityPresent
		if len(c.DelegationSecret) > 0 {
			// Resolve identity lazily so the status tool also works before the
			// first call, and reports a concrete cause instead of a bare false.
			_ = c.EnsureDelegationIdentity(ctx)
		}
		ok, why := c.DelegationConfigured()
		res := &jmsms.DelegationStatus{
			Configured: ok && hasScheme,
			BaseURL:    jms.Opt(c.BaseURL),
			UserID:     jms.Opt(c.DelegationUserID),
			OrgID:      jms.Opt(c.DelegationOrgID),
			KeyID:      jms.Opt(c.DelegationKeyID),
		}
		if state == jmsapi.CapabilityAbsent {
			res.Reason = jms.Opt(jmsapi.Explain(jmsapi.CapDelegation, state))
			res.HowToConfigure = jms.Opt(jmsapi.Advice(jmsapi.CapDelegation, state))
			return render.Text(res)
		}
		if state == jmsapi.CapabilityUnknown {
			res.Reason = jms.Opt(jmsapi.Explain(jmsapi.CapDelegation, state))
			res.HowToConfigure = jms.Opt(jmsapi.Advice(jmsapi.CapDelegation, state))
			return render.Text(res)
		}
		if !ok {
			res.Reason = jms.Opt(why)
			res.HowToConfigure = jms.Opt("write the bastion's CHAT_AI_DELEGATION_SECRET to " +
				"~/.config/jumpserver-mgmt/delegation.key with mode 0600, or set JMS_DELEGATION_SECRET. " +
				"JMS_DELEGATION_USER_ID and JMS_DELEGATION_ORG_ID identify who and which org the call acts as.")
			return render.Text(res)
		}
		res.Binds = []string{
			"X-JMS-AI-Operation must equal the token's allowed_operation_id",
			"method, path, query string and body are hashed into the token",
			"single-use nonce: a replay is rejected with 'already used'",
			"X-JMS-ORG header is required (the same-named cookie is a fallback and is not required)",
		}
		res.Note = jms.Opt("the secret is read once at startup and never returned by any tool")
		return render.Text(res)
	})

	type callArgs struct {
		Method      string `json:"method" jsonschema:"HTTP method, e.g. GET / POST / PATCH / DELETE"`
		Path        string `json:"path" jsonschema:"API path under /api/v1, e.g. /assets/assets/"`
		Query       string `json:"query,omitempty" jsonschema:"query string without the leading '?'"`
		Body        string `json:"body,omitempty" jsonschema:"JSON request body as a string"`
		OperationID string `json:"operation_id,omitempty" jsonschema:"label for the audit trail, e.g. assets.view_asset (core only checks header/token agreement)"`
		Raw         bool   `json:"raw,omitempty" jsonschema:"return the raw response text instead of a summary"`
		Confirm     bool   `json:"confirm,omitempty" jsonschema:"must be true when the method changes something (POST / PATCH / PUT / DELETE). A read (GET / HEAD) does not need it"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_delegation_call",
		Description: "Call any JumpServer API endpoint with a freshly minted, single-use Chat AI delegation " +
			"credential instead of the long-lived token. Use it for operations you would not want permanently " +
			"reachable (deletes, permission changes, account resets): if the credential leaks it is already spent, " +
			"and it cannot be re-pointed at another endpoint. It cannot grant access the configured user lacks.",
		OutputSchema: render.Schema[jmsms.DelegationCallResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args callArgs) (*mcp.CallToolResult, any, error) {
		method := strings.ToUpper(strings.TrimSpace(args.Method))
		path := strings.TrimSpace(args.Path)
		if method == "" || path == "" {
			return render.Failf("both method and path are required")
		}
		// The method is the caller's choice, so the method decides whether
		// this call changes anything. A read needs no confirmation; a write
		// does, and the tool says so instead of doing it.
		//
		// The check comes before the delegation is set up on purpose: the
		// credential is single-use, so a refused call must not burn it.
		if !jmsapi.IsReadMethod(method) && !args.Confirm {
			return render.Text(&jmsms.DelegationCallResult{
				Method: jms.Opt(method),
				Path:   jms.Opt(path),
				Blocked: jms.Opt("the " + method + " call would change the bastion; " +
					"re-call with confirm=true to execute"),
			})
		}
		if err := c.EnsureDelegationIdentity(ctx); err != nil {
			return render.Failf("delegation is not ready: %v. Run jms_delegation_status for how to set it up", err)
		}
		// The gate: the credential is minted only when the deployment is
		// KNOWN to have the scheme.
		//
		// ⚠️ It is an `if` with an early return, not a `switch`: the
		// mechanical guard in internal/arch recognises this shape, and a
		// shape it does not recognise is a call site it cannot vouch for.
		//
		// ⚠️ UNKNOWN is refused here, even though the execution plane
		// presents on unknown: a delegation credential cannot be minted
		// without the scheme, so trying would only produce a 401 — and a 401
		// on this path reads as "the credential is wrong".
		if state := c.Profile(ctx).State(jmsapi.CapDelegation); state != jmsapi.CapabilityPresent {
			return render.Failf("%s; %s",
				jmsapi.Reason(jmsapi.CapDelegation, state),
				jmsapi.Advice(jmsapi.CapDelegation, state))
		}
		if ok, why := c.DelegationConfigured(); !ok {
			return render.Failf("delegation is not configured: %s. Run jms_delegation_status for how to set it up", why)
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		var body []byte
		if args.Body != "" {
			body = []byte(args.Body)
			if !json.Valid(body) {
				return render.Failf("body must be valid JSON")
			}
		}
		query := strings.TrimPrefix(strings.TrimSpace(args.Query), "?")

		call := repository.DelegationCall{
			Method:      method,
			Path:        path,
			Query:       query,
			Body:        body,
			OperationID: repository.StrDefault("ai.delegation_call", args.OperationID),
		}
		status, raw, err := c.DelegationRequest(ctx, call)
		if err != nil {
			return render.Failf("delegation call failed: %v", err)
		}

		res := &jmsms.DelegationCallResult{
			Status:      jms.OptInt32(int32(status)),
			Method:      jms.Opt(method),
			Path:        jms.Opt(path),
			Query:       jms.Opt(query),
			OperationID: jms.Opt(call.OperationID),
			Credential:  jms.Opt("single-use, bound to this request, valid ~55s"),
			Bytes:       jms.OptInt32(int32(len(raw))),
		}
		if status >= 400 {
			res.ErrorBody = jms.Opt(jmsapi.Truncate(string(raw), 600))
			res.Note = jms.Opt("core rejected the request; the most common cause is that the user lacks the RBAC " +
				"permission, since delegation adds no access of its own")
			return render.Text(res)
		}
		if args.Raw {
			res.Body = jms.Opt(jmsapi.Truncate(string(raw), 20000))
			return render.Text(res)
		}
		var parsed any
		if json.Unmarshal(raw, &parsed) == nil {
			if rows, ok := parsed.([]any); ok {
				res.Count = jms.OptInt32(int32(len(rows)))
				res.Preview = jms.Opt(jmsapi.Truncate(string(raw), 3000))
			} else {
				// The body is TEXT, not an object, and that is the whole point
				// of the change: the contract says the body is a string, and
				// handing over the parsed object made every paginated
				// endpoint fail its own output check.
				//
				// What the caller asked for is the bastion's answer as it
				// came, so the raw text is what goes back.
				res.Body = jms.Opt(jmsapi.Truncate(string(raw), 20000))
			}
		} else {
			res.Body = jms.Opt(jmsapi.Truncate(string(raw), 4000))
		}
		return render.Text(res)
	})

	type probeArgs struct {
		OperationID string `json:"operation_id,omitempty" jsonschema:"label for the audit trail"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_delegation_probe",
		Description: "Verify the delegation credential end to end and show how core reacts to each binding. " +
			"Read-only: it only lists assets, and every rejection it reports is core refusing a deliberately " +
			"mismatched credential. Use it when you need proof the scheme is live on this bastion rather than " +
			"a claim that it should be.",
		OutputSchema: render.Schema[jmsms.DelegationProbe](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args probeArgs) (*mcp.CallToolResult, any, error) {
		if err := c.EnsureDelegationIdentity(ctx); err != nil {
			return render.Failf("delegation is not ready: %v", err)
		}
		// The gate: the credential is minted only when the deployment is
		// KNOWN to have the scheme.
		//
		// ⚠️ It is an `if` with an early return, not a `switch`: the
		// mechanical guard in internal/arch recognises this shape, and a
		// shape it does not recognise is a call site it cannot vouch for.
		//
		// ⚠️ UNKNOWN is refused here, even though the execution plane
		// presents on unknown: a delegation credential cannot be minted
		// without the scheme, so trying would only produce a 401 — and a 401
		// on this path reads as "the credential is wrong".
		if state := c.Profile(ctx).State(jmsapi.CapDelegation); state != jmsapi.CapabilityPresent {
			return render.Failf("%s; %s",
				jmsapi.Reason(jmsapi.CapDelegation, state),
				jmsapi.Advice(jmsapi.CapDelegation, state))
		}
		if ok, why := c.DelegationConfigured(); !ok {
			return render.Failf("delegation is not configured: %s. Run jms_delegation_status for how to set it up", why)
		}
		op := repository.StrDefault("assets.view_asset", args.OperationID)
		ids, meta, err := c.ResolveAssets(ctx, []string{"node-071"})
		if err != nil {
			return render.Failf("%v", err)
		}
		_ = ids
		_ = meta

		base := repository.DelegationCall{Method: "GET", Path: jmsapi.DelegationPath(jmsapi.ResAssets),
			Query: "page_size=1", OperationID: op}

		// Mint ONE credential, then present it to requests it was not bound to.
		// Minting per attempt would make every case correctly signed, and a
		// correctly signed request succeeding proves nothing about the binding.
		token, err := c.MintDelegation(base)
		if err != nil {
			return render.Failf("mint failed: %v", err)
		}

		type probeCase struct {
			name   string
			call   repository.DelegationCall
			expect string
		}
		cases := []probeCase{
			{"valid", base, "the control: must be 2xx"},
			{"replay", base, "same credential a second time"},
			{"operation_mismatch", repository.DelegationCall{Method: base.Method, Path: base.Path,
				Query: base.Query, OperationID: op + ".tampered"},
				"header operation differs from the token"},
			{"path_mismatch", repository.DelegationCall{Method: base.Method,
				Path: jmsapi.DelegationPath(jmsapi.ResAssetHosts), Query: base.Query,
				OperationID: base.OperationID}, "token bound to another path"},
			{"method_mismatch", repository.DelegationCall{Method: "POST", Path: base.Path,
				Query: base.Query, OperationID: base.OperationID}, "token bound to GET"},
			{"query_mismatch", repository.DelegationCall{Method: base.Method, Path: base.Path,
				Query: "page_size=9", OperationID: base.OperationID},
				"query is hashed into the token"},
		}

		out := []*jmsms.DelegationCheck{}
		for _, tc := range cases {
			status, raw, err := c.SendWithDelegation(ctx, token, tc.call)
			entry := &jmsms.DelegationCheck{Case: tc.name, Expect: tc.expect}
			if err != nil {
				entry.TransportError = jms.Opt(err.Error())
			} else {
				entry.Status = jms.OptInt32(int32(status))
				if status >= 400 {
					entry.CoreSays = jms.Opt(jmsapi.Truncate(strings.TrimSpace(string(raw)), 200))
				}
			}
			out = append(out, entry)
		}

		// A second, independently minted credential must work again: single-use
		// must mean single-use, not "the scheme only ever works once".
		fresh, ferr := c.MintDelegation(base)
		st2 := 0
		if ferr == nil {
			st2, _, _ = c.SendWithDelegation(ctx, fresh, base)
		}
		out = append(out, &jmsms.DelegationCheck{
			Case: "second_fresh_credential", Expect: "a newly minted one must work",
			Status: jms.OptInt32(int32(st2)),
		})

		res := &jmsms.DelegationProbe{
			UserID: jms.Opt(c.DelegationUserID),
			OrgID:  jms.Opt(c.DelegationOrgID),
			Checks: out,
			Note: jms.Opt("'valid' and 'second_fresh_credential' must be 2xx; every other case must be " +
				"401 with core naming WHICH binding failed. Distinct messages are the evidence " +
				"that the credential is bound, not merely signed."),
		}
		return render.Text(res)
	})
}
