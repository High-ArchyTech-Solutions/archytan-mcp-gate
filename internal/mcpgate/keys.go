// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A JSON object whose keys repeat, or differ only in case, reads two ways.
// A repeated key is the last one to JavaScript, Python and Go but the
// first to some parsers, and Go's encoding/json matches struct fields
// without regard to case. So {"method":"tools/call","Method":"tools/list"}
// was tools/list to this gate, a request it forwards ungated, and
// tools/call to a server in JavaScript, which ran the tool; and
// {"name":"drop_database","Name":"delete_invoice"} was authorized as
// delete_invoice and run as drop_database. The gate refuses a host message
// like that at every level it reads to decide: the envelope, its params,
// and the arguments in them. Below those levels it reads nothing.
//
// Text has the same problem. Go's encoding/json turns invalid UTF-8 and an
// unpaired surrogate escape ("\ud800") into U+FFFD, so "inv_\ud800" and
// "inv_\udfff" both become "inv_" and U+FFFD to the gate, while JavaScript keeps
// each as it was: the receipt would name a resource the server never saw.
// The gate refuses those anywhere in a host message. The rule throughout
// is to refuse what can be read two ways, rather than pick a reading.

var errAmbiguousKeys = errors.New("keys that repeat or differ only in case")

var errAmbiguousText = errors.New("text that isn't valid UTF-8 or has an unpaired surrogate escape")

// checkText refuses a message that isn't valid UTF-8 or that escapes a
// surrogate outside a high-low pair. The line has already parsed as JSON,
// so outside strings it holds no backslashes, and inside them every
// backslash starts a well-formed escape.
func checkText(line []byte) error {
	if !utf8.Valid(line) {
		return errAmbiguousText
	}
	inString := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '"':
			inString = !inString
		case c == '\\' && inString:
			if i+1 < len(line) && line[i+1] == 'u' {
				r, ok := escapedRune(line, i)
				if !ok {
					return errAmbiguousText
				}
				switch {
				case r >= 0xD800 && r <= 0xDBFF:
					low, ok := escapedRune(line, i+6)
					if !ok || low < 0xDC00 || low > 0xDFFF {
						return errAmbiguousText
					}
					i += 11
				case r >= 0xDC00 && r <= 0xDFFF:
					return errAmbiguousText
				default:
					i += 5
				}
			} else {
				i++ // a one-character escape, \" included
			}
		}
	}
	return nil
}

// escapedRune reads the \uXXXX escape starting at line[i].
func escapedRune(line []byte, i int) (rune, bool) {
	if i+6 > len(line) || line[i] != '\\' || line[i+1] != 'u' {
		return 0, false
	}
	var r rune
	for _, h := range line[i+2 : i+6] {
		r <<= 4
		switch {
		case h >= '0' && h <= '9':
			r |= rune(h - '0')
		case h >= 'a' && h <= 'f':
			r |= rune(h-'a') + 10
		case h >= 'A' && h <= 'F':
			r |= rune(h-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}

// foldKey maps a key to one representative of its case-folding class: two
// keys get the same result exactly when strings.EqualFold says they are
// equal, which is also how encoding/json matches a key to a struct field.
// Each rune becomes the smallest rune in its simple-folding orbit, so
// "status" and "ſtatus" (long s) collide, as they do for encoding/json.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < least {
				least = f
			}
		}
		b.WriteRune(least)
	}
	return b.String()
}

// objectFields decodes a JSON object's members, refusing an object whose
// keys repeat or differ only in case (errAmbiguousKeys). A value that
// isn't an object gives nil and no error: whether it may be something
// else is for the caller to decide.
func objectFields(raw []byte) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("object key %v is not a string", tok)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if first, dup := seen[foldKey(key)]; dup {
			return nil, fmt.Errorf("%w: %q and %q", errAmbiguousKeys, first, key)
		}
		seen[foldKey(key)] = key
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return fields, nil
}

// checkKeysEverywhere refuses JSON with an object, at any depth, whose keys
// repeat or differ only in case. where names the value in the error. Host
// messages are checked only at the levels the gate reads; the gate's own
// config is read whole, so it is checked whole.
func checkKeysEverywhere(raw []byte, where string) error {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '{':
		fields, err := objectFields(trimmed)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := checkKeysEverywhere(fields[k], where+"."+k); err != nil {
				return err
			}
		}
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		for i, item := range items {
			if err := checkKeysEverywhere(item, fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkUnambiguous refuses a host message with ambiguous text anywhere, or
// with ambiguous keys in its envelope, its params or the arguments in them.
func checkUnambiguous(line []byte) error {
	if err := checkText(line); err != nil {
		return err
	}
	env, err := objectFields(line)
	if err != nil {
		return err
	}
	for k, v := range env {
		if !strings.EqualFold(k, "params") {
			continue
		}
		params, err := objectFields(v)
		if err != nil {
			return fmt.Errorf("params: %w", err)
		}
		for pk, pv := range params {
			if !strings.EqualFold(pk, "arguments") {
				continue
			}
			if _, err := objectFields(pv); err != nil {
				return fmt.Errorf("arguments: %w", err)
			}
		}
	}
	return nil
}
