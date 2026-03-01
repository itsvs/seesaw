package policyengine

import "github.com/itsvs/seesaw/goutils/errors"

// ErrNoTerminalOutput is returned by an engine when no terminal output is found.
const ErrNoTerminalOutput = errors.Constant("no terminal output")
