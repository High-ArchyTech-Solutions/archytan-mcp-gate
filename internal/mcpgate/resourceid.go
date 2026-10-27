// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Resource ids built from several tool arguments.
//
// Many tool servers name the thing a call acts on with more than one
// argument: a code host takes an owner and a repo, a deploy tool an
// environment and a service. resource_id_args joins those values with "/"
// into the one id Archytan Lite matches against a grant, so a grant such as
// "acme/web-*" can scope them.
//
// Joining is where the danger is. Once joined, owner "a/b" with repo "c"
// reads the same as owner "a" with repo "b/c", and Lite, which sees only
// the joined id, can't tell which argument a segment came from. Only the
// gate can, so the gate refuses a separator inside any resource_id_args
// value; only resource_id_path_arg, which always comes last, may span
// several segments, since nothing follows it for a segment to be moved
// into. Everything else about the id is Lite's to judge: under a rule
// scoped by resource it refuses an id with a ".." or empty segment, a
// character outside its grammar, or both separators, before any grant is
// matched, so the gate doesn't keep a second copy of that grammar.
//
// A listed argument that is missing is refused rather than left out of the
// id. A tool that fills in a default for it, such as the default branch,
// would otherwise act on a resource the id doesn't name.

// resourceID returns the resource id a call to a tool mapped by m acts on,
// or why it can't be read from args. The error reads as the rest of a
// sentence that starts with the tool's name.
func (m ToolMapping) resourceID(args map[string]json.RawMessage) (string, error) {
	if len(m.ResourceIDArgs) == 0 {
		return stringArg(args, m.ResourceIDArg)
	}
	parts := make([]string, 0, len(m.ResourceIDArgs)+1)
	for _, name := range m.ResourceIDArgs {
		v, err := stringArg(args, name)
		if err != nil {
			return "", err
		}
		if strings.ContainsAny(v, `/\`) {
			return "", fmt.Errorf("needs argument %q to be a single name, and %q contains a separator, so joined with the other arguments it would name a different resource", name, v)
		}
		parts = append(parts, v)
	}
	if name := m.ResourcePathArg; name != "" {
		v, err := stringArg(args, name)
		if err != nil {
			return "", err
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, "/"), nil
}

// stringArg returns the value of the named argument, which must be a
// non-empty JSON string: a missing argument, a null, a number, or any
// other type is refused, never turned into text.
func stringArg(args map[string]json.RawMessage, name string) (string, error) {
	var v *string
	raw, ok := args[name]
	if !ok || json.Unmarshal(raw, &v) != nil || v == nil || *v == "" {
		return "", fmt.Errorf("needs a non-empty string argument %q to identify the resource", name)
	}
	return *v, nil
}
