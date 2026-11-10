package repository

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The repository layer used to throw the caller's ctx away (#11): both
// delegation methods hard-coded context.Background(), so an MCP client that
// disconnected left the JumpServer side running to the end — the single-use
// credential consumed server-side while the client read the silence as
// "failed, may retry". These tests pin the OTHER behaviour: the caller's
// cancellation reaches the outbound request, and the server sees it.

// cancelObservingServer answers nothing until its request's context is done:
// the handler blocks, records the cancellation, and lets the call fail. It
// also announces each arrival, so a test can cancel AFTER the request is in
// flight (cancelling before the first byte would prove nothing about the
// wire — the http layer would fail without sending).
func cancelObservingServer(t *testing.T) (srv *httptest.Server, arrived, sawCancel chan struct{}) {
	t.Helper()
	arrived = make(chan struct{}, 1)
	sawCancel = make(chan struct{}, 1)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
			select {
			case sawCancel <- struct{}{}:
			default:
			}
		case <-time.After(4 * time.Second):
			// The request ran to completion — the behaviour the old
			// context.Background() wrapper produced.
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, arrived, sawCancel
}

// delegationTestClient wires a repository client at the test server with the
// delegation settings config() needs.
func delegationTestClient(url string) *Client {
	c := NewBase(url, "t", nil)
	c.DelegationSecret = []byte("s3cret")
	c.DelegationUserID = "u1"
	c.DelegationOrgID = "o1"
	return c
}

// DelegationRequest must carry the caller's ctx: cancelling it cancels the
// outbound request (the server observes ctx.Done), and the call returns an
// error instead of running to a success the caller will never read.
func TestDelegationRequestCarriesTheCallersContext(t *testing.T) {
	srv, arrived, sawCancel := cancelObservingServer(t)
	c := delegationTestClient(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.DelegationRequest(ctx, DelegationCall{Method: "GET", Path: "/api/v1/x"})
		errc <- err
	}()

	<-arrived // the request is on the wire; NOW the client goes away
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Error("the call succeeded after the caller cancelled — the client would read a retryable failure while the credential was spent")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the call did not return after the caller cancelled")
	}
	select {
	case <-sawCancel:
	case <-time.After(3 * time.Second):
		t.Error("the outbound request kept running after the caller cancelled — the JumpServer side was left to run to completion")
	}
}

// SendWithDelegation carries the caller's ctx for the same reason: the probe
// checks it sends are still the caller's requests, not detached ones.
func TestSendWithDelegationCarriesTheCallersContext(t *testing.T) {
	srv, arrived, sawCancel := cancelObservingServer(t)
	c := delegationTestClient(srv.URL)

	call := DelegationCall{Method: "GET", Path: "/api/v1/x"}
	token, err := c.MintDelegation(call)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.SendWithDelegation(ctx, token, call)
		errc <- err
	}()

	<-arrived
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Error("the call succeeded after the caller cancelled")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the call did not return after the caller cancelled")
	}
	select {
	case <-sawCancel:
	case <-time.After(3 * time.Second):
		t.Error("the outbound request kept running after the caller cancelled")
	}
}

// A healthy ctx still completes the round trip: the cancellation wiring must
// not have broken the ordinary path.
func TestDelegationRequestStillRoundTripsUncancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	t.Cleanup(srv.Close)
	c := delegationTestClient(srv.URL)

	status, raw, err := c.DelegationRequest(context.Background(), DelegationCall{Method: "GET", Path: "/api/v1/x"})
	if err != nil {
		t.Fatalf("DelegationRequest: %v", err)
	}
	if status != http.StatusOK || string(raw) == "" {
		t.Errorf("status=%d body=%q, want 200 with the body", status, raw)
	}
}
