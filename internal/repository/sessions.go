// Part of the management plane's repository over the JumpServer API.
//
// The transport and the parsing of the two response shapes v5 mixes live in
// jms-kit/pkg/jmsapi; what is here is the questions the tools ask and the
// resources they get back.
package repository

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"

	"github.com/oekit/pkg/convert"
)

func (c *Client) SessionAssetIDs(ctx context.Context, ref string) ([]string, []map[string]any, error) {
	sessions, err := c.List(ctx, jmsapi.ResSessions)
	if err != nil {
		return nil, nil, err
	}
	low := strings.ToLower(strings.TrimSpace(ref))
	byID := map[string]map[string]string{}
	for _, s := range sessions {
		name := strings.ToLower(fmt.Sprint(jmsapi.AssetField(s, "name")))
		addr := strings.ToLower(fmt.Sprint(jmsapi.AssetField(s, "address")))
		if name != low && addr != low {
			continue
		}
		id := fmt.Sprint(jmsapi.AssetField(s, "id"))
		if id == "" || id == "<nil>" {
			continue
		}
		if _, ok := byID[id]; !ok {
			byID[id] = map[string]string{"name": name, "address": addr}
		}
	}
	ids := make([]string, 0, len(byID))
	meta := make([]map[string]any, 0, len(byID))
	for id, v := range byID {
		ids = append(ids, id)
		meta = append(meta, map[string]any{"id": id, "name": v["name"], "address": v["address"]})
	}
	slices.Sort(ids)
	slices.SortStableFunc(meta, func(a, b map[string]any) int {
		return strings.Compare(convert.AnyToStr(a["id"]), convert.AnyToStr(b["id"]))
	})
	return ids, meta, nil
}

func (c *Client) DownloadReplayText(ctx context.Context, sessionID string) (string, error) {
	// The archive is not JSON, so it goes through the binary fetch — which
	// also carries the credential's own header. Hand-building "Token "+token
	// here sent "Token " with an EMPTY key under a login credential (v4's
	// only option), and the 401 that came back was read as a tar stream and
	// reported "unexpected EOF" instead of a refused credential.
	//
	// STREAMED TO DISK, not held in memory: a long session's replay archive
	// reaches gigabytes, and evidence pulls run several of them in one tool
	// call — GetBinary would hold every one of them (plus the tar and cast
	// copies on top) in RAM at once. GetBinaryTo pipes the body straight
	// into a scratch file, deleted when this function returns; only the
	// (compressed-then-text) cast member inside is ever read whole.
	tmp, err := os.CreateTemp("", "jms-replay-*.tar")
	if err != nil {
		return "", fmt.Errorf("scratch file for replay: %w", err)
	}
	path := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(path) }()
	if _, err := c.GetBinaryTo(ctx, string(jmsapi.ResSessions)+sessionID+"/replay/download/", tmp); err != nil {
		return "", err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return castTextFromFile(tmp)
}

// castTextFromFile walks a replay tar already on disk and returns the text
// of its .cast.gz member. The tar itself is streamed from the file; the
// cast member is decompressed streaming and read whole only at the text
// conversion, where the input is JSON lines a fraction of the archive size.
func castTextFromFile(f *os.File) (string, error) {
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read replay tar: %w", err)
		}
		if !strings.HasSuffix(hdr.Name, ".cast.gz") {
			continue
		}
		zr, err := gzip.NewReader(tr)
		if err != nil {
			return "", fmt.Errorf("gunzip cast: %w", err)
		}
		raw, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			return "", fmt.Errorf("read cast body: %w", err)
		}
		return AsciinemaToText(raw), nil
	}
	return "", fmt.Errorf("no .cast.gz member in the replay archive")
}

func AsciinemaToText(raw []byte) string {
	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row []json.RawMessage
		if json.Unmarshal([]byte(line), &row) != nil || len(row) < 3 {
			continue
		}
		var kind, data string
		if json.Unmarshal(row[1], &kind) != nil || json.Unmarshal(row[2], &data) != nil {
			continue
		}
		if kind == "o" {
			b.WriteString(data)
		}
	}
	return b.String()
}
