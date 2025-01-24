// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package osv

import "github.com/carabiner-dev/osv/go/osv/v1_6_7"

const (
	Version = "v1.6.7"
)

// We maintain type aliases of the latest proto generated structures.
// This ensures any new record gets generated with the latest revision
// but keeps the older versions still available.
type (
	Affected    = v1_6_7.Affected
	Award       = v1_6_7.Award
	Credit      = v1_6_7.Credit
	CWE         = v1_6_7.CWE
	Range       = v1_6_7.Range
	Range_Event = v1_6_7.Range_Event
	Record      = v1_6_7.Record
	Reference   = v1_6_7.Reference
	Severity    = v1_6_7.Severity
	Package     = v1_6_7.Package
)
