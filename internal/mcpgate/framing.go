// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// MaxMessageBytes caps one newline-delimited JSON-RPC message. Tool
// results routinely exceed bufio.Scanner's 64 KiB default (file reads,
// schema dumps, page snapshots), so lines are read with a growing buffer;
// the cap only stops a runaway stream from exhausting memory.
const MaxMessageBytes = 32 << 20

// ErrMessageTooLarge ends the session: a message cut short cannot be
// forwarded, and guessing at the rest is not an option.
var ErrMessageTooLarge = errors.New("mcpgate: message exceeds the size cap")

// readLine returns the next line without its trailing newline. A final
// line without a newline is still returned; io.EOF means no more input.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > max {
			return nil, ErrMessageTooLarge
		}
		buf = append(buf, chunk...)
		switch {
		case err == nil:
			return bytes.TrimRight(buf, "\r\n"), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(buf) > 0:
			return bytes.TrimRight(buf, "\r\n"), nil
		default:
			return nil, err
		}
	}
}

// lineWriter writes whole messages, one per line, from any goroutine.
type lineWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *lineWriter) write(msg []byte) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	buf := make([]byte, 0, len(msg)+1)
	buf = append(buf, msg...)
	buf = append(buf, '\n')
	_, err := lw.w.Write(buf)
	return err
}

// message is the envelope of every JSON-RPC 2.0 message. ID stays raw:
// hosts send strings, numbers and occasionally null, and a synthetic reply
// must echo whichever it was, byte for byte.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (m *message) hasID() bool          { return len(m.ID) > 0 }
func (m *message) isRequest() bool      { return m.Method != "" && m.hasID() }
func (m *message) isNotification() bool { return m.Method != "" && !m.hasID() }
func (m *message) isResponse() bool     { return m.Method == "" && m.hasID() }

// parseMessage decodes one line. A top-level array (a JSON-RPC batch) is
// reported separately: current MCP has no batches, and this gate refuses
// them rather than unpack one and risk gating only part of it.
func parseMessage(line []byte) (msg *message, isBatch bool, err error) {
	trimmed := bytes.TrimLeft(line, " \t")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, true, errors.New("batch")
	}
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, false, err
	}
	return &m, false, nil
}

func errorResponse(id json.RawMessage, code int, text string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	out, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id, Error: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{code, text}})
	return out
}

// toolRefusal is a tools/call result carrying the refusal as text, with
// isError set. A JSON-RPC error tends to reach a model as "something went
// wrong, retry", which produces a retry storm against a gate that has
// already said no; a sentence explaining the refusal is something the
// model can reason about and stop on.
//
// Under MCP 2026-07-28 every result names its type and a client rejects a
// result without one, so a refusal of a call made under those rules
// (modern) says it is complete. An older client gets the shape it always
// has.
func toolRefusal(id json.RawMessage, text string, modern bool) []byte {
	type content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type result struct {
		ResultType string    `json:"resultType,omitempty"`
		Content    []content `json:"content"`
		IsError    bool      `json:"isError"`
	}
	r := result{Content: []content{{Type: "text", Text: text}}, IsError: true}
	if modern {
		r.ResultType = "complete"
	}
	out, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  result          `json:"result"`
	}{JSONRPC: "2.0", ID: id, Result: r})
	return out
}
