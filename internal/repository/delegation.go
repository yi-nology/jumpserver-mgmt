package repository

// The management plane's view of the Chat AI delegation scheme.
//
// The SCHEME lives in pkg/jmsapi: the payload core signs, the request binding
// hash, the header names and the TTL. It is there because the execution plane
// needs the same thing — it mints a connection token AS the delegated user, so
// a session on a machine carries that user's authority instead of the API
// token owner's — and the two planes may not import each other.
//
// What is here is the wiring: this client's own delegation settings, and the
// handful of methods the tools call. They are thin on purpose. The rules that
// decide whether a credential is accepted by core are all in one place now,
// and a second copy of them would drift into "request mismatch" — core's way
// of saying the two sides disagree about what was signed.
//
// Why delegation exists at all: a long-lived API token is all-or-nothing —
// anyone holding it can call anything the user can, for as long as it lives,
// and nothing in core distinguishes "a human's token" from "an agent's token".
// JumpServer ships a narrower scheme for AI callers, and it is live on this
// deployment (CHAT_AI_DELEGATION_SECRET is set, and the authentication class
// is registered globally in DEFAULT_AUTHENTICATION_CLASSES).
//
// A delegation credential is bound, and core verifies every binding. Measured
// 2026-10-15 against a live bastion, each of these was rejected:
//
//	missing X-JMS-ORG            -> "organization mismatch"
//	operation header != token    -> "operation mismatch"
//	different path               -> "request mismatch"
//	different query string       -> "request body mismatch"
//	different method             -> "request mismatch"
//	same token twice             -> "credential was already used"  (single-use nonce)
//
// So the credential authorises exactly one call: one method, one path, one
// query, one body, once, within 60 seconds. That is a different security
// property from a bearer token, not a different amount of access — it is worth
// having for operations you would rather not leave permanently reachable.
//
// What it does NOT do: it does not grant access the user lacks. The returned
// user is fed into the normal RBAC pipeline, and `allowed_operation_id` is only
// checked for consistency between the header and the token, not against the
// endpoint. Any access the caller already has, delegation cannot widen.

import (
	"context"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

const (
	delegationKeyID           = jmsapi.DefaultDelegationKeyID
	defaultDelegationIssuer   = jmsapi.DefaultDelegationIssuer
	defaultDelegationAudience = jmsapi.DefaultDelegationAudience
)

// DelegationCall describes the single request a credential will be spent on.
//
// It is an alias, not a copy: the execution plane signs the same payload, and
// two types would be two chances to spell the binding differently.
type DelegationCall = jmsapi.DelegationCall

// config assembles this client's delegation settings into the shared shape.
func (c *Client) config() jmsapi.DelegationConfig {
	return jmsapi.DelegationConfig{
		Secret:   c.DelegationSecret,
		KeyID:    c.DelegationKeyID,
		Issuer:   c.DelegationIssuer,
		Audience: c.DelegationAudience,
		OrgID:    c.DelegationOrgID,
		UserID:   c.DelegationUserID,
	}
}

// DelegationConfigured reports whether this process is configured for the
// delegation scheme: a secret, and an identity.
//
// ⚠️ It is the SECOND of the two questions. The FIRST one — does the
// deployment have the scheme at all — is asked with
// `c.State(ctx, jmsapi.CapDelegation)`, and the two are kept apart because
// the answers call for different things: the first cannot be fixed by
// configuring anything, the second can.
func (c *Client) DelegationConfigured() (bool, string) {
	return c.Client.DelegationConfigured(c.config())
}

// EnsureDelegationIdentity fills in the user and org the credential acts as.
func (c *Client) EnsureDelegationIdentity(ctx context.Context) error {
	cfg := c.config()
	if err := c.Client.EnsureDelegationIdentityAs(ctx, &cfg, "ai"); err != nil {
		return err
	}
	// The resolved ids are read back from the shared holder rather than
	// from the config's own fields: those fields are what several sessions
	// share, and writing them from here is the race the holder prevents.
	userID, orgID, _ := cfg.Identity()
	c.DelegationUserID = userID
	c.DelegationOrgID = orgID
	return nil
}

// MintDelegation produces the `payload.signature` token for one call.
func (c *Client) MintDelegation(call DelegationCall) (string, error) {
	return c.Client.MintDelegation(c.config(), call)
}

// DelegationRequest performs one request authorised by a freshly minted,
// single-use credential. It returns the status and body without going through
// the token-based client, because the whole point is that this call does NOT
// carry the long-lived token.
//
// The ctx is the CALLER's: cancelling it cancels the outbound request (#11 —
// this used to hard-code context.Background(), so an MCP client that went away
// left the JumpServer side running to completion and the single-use credential
// consumed, while the client read the silence as "failed, may retry").
func (c *Client) DelegationRequest(ctx context.Context, call DelegationCall) (int, []byte, error) {
	return c.Client.DelegationRequest(ctx, c.config(), call)
}

// SendWithDelegation performs a request with an ALREADY-minted credential.
//
// It exists so the boundary of that credential can be observed: handing the same
// token a different path, method, query or operation id has to fail, and that
// can only be checked by sending a token whose signature no longer matches the
// request. Minting a fresh token per attempt would prove nothing — every such
// attempt would be correctly signed and therefore correctly accepted.
// The ctx travels for the same reason as DelegationRequest's (#11).
func (c *Client) SendWithDelegation(ctx context.Context, token string, call DelegationCall) (int, []byte, error) {
	return c.Client.SendWithDelegation(ctx, token, c.config(), call)
}

// LoadDelegationSecret resolves the secret without ever printing it.
//
// Order: explicit environment variable, then a 0600 file. The file is the
// recommended home for it — the value is a bastion-wide root of trust for AI
// callers, and putting it in an MCP config file would spread it to every
// process that can read that directory.
func LoadDelegationSecret() ([]byte, error) {
	return jmsapi.LoadDelegationSecret()
}

// StrDefault returns v when it is not empty and the fallback otherwise.
//
// It is used for operation ids, which core only checks for consistency: an
// empty one would still work, but an unreadable audit entry is worse than a
// default.
func StrDefault(fallback, v string) string {
	if v == "" {
		return fallback
	}
	return v
}
