// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package osv

import (
	v1 "github.com/carabiner-dev/osv/go/osv/v1"
	"github.com/carabiner-dev/osv/go/osv/v1_6_7"
)

const (
	Version = "v1"
)

// The osv package aliases point at the current OSV record definition (v1,
// generated from the upstream ossf/osv-schema proto). The v1_6_7 package is
// retained frozen for backwards compatibility.
type (
	Affected    = v1.Affected
	Credit      = v1.Credit
	Event       = v1.Event
	Range       = v1.Range
	Range_Event = v1.Event
	Record      = v1.Vulnerability
	Reference   = v1.Reference
	Severity    = v1.Severity
	Package     = v1.Package

	// CWE and Award are not part of the upstream OSV schema; they are retained
	// from the frozen v1.6.7 definitions for backwards compatibility.
	CWE   = v1_6_7.CWE
	Award = v1_6_7.Award
)
