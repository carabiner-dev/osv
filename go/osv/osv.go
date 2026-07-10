// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package osv

import "github.com/carabiner-dev/osv/go/osv/v1"

const (
	Version = "v1"
)

// We maintain type aliases of the latest proto generated structures.
// This ensures any new record gets generated with the latest revision
// but keeps the older versions still available.
type (
	Affected    = v1.Affected
	Award       = v1.Award
	Credit      = v1.Credit
	CWE         = v1.CWE
	Range       = v1.Range
	Range_Event = v1.Range_Event
	Record      = v1.Record
	Reference   = v1.Reference
	Severity    = v1.Severity
	Package     = v1.Package
)
