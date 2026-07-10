// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package grype

import (
	"os"
	"testing"

	"github.com/carabiner-dev/osv/go/osv"
	"github.com/carabiner-dev/osv/go/osv/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestToOSV(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/grype.json")
	require.NoError(t, err)

	doc, err := Parse(data)
	require.NoError(t, err)
	require.NotEmpty(t, doc.Matches)

	results, err := doc.ToOSV()
	require.NoError(t, err)
	require.NotNil(t, results)
	require.NotNil(t, results.GetDate(), "descriptor timestamp should populate results date")
	require.Len(t, results.GetResults(), 1, "grype emits a single source")

	res := results.GetResults()[0]
	require.Equal(t, "file", res.GetSource().GetType())
	require.Equal(t, "go.mod", res.GetSource().GetPath())
	require.NotEmpty(t, res.GetPackages())

	record := findRecord(results, "GHSA-9jj7-4m8r-rfcm")
	require.NotNil(t, record, "expected GHSA-9jj7-4m8r-rfcm in the converted results")
	require.NotEmpty(t, record.GetDetails())

	// Related vulnerabilities become aliases.
	require.Contains(t, record.GetAliases(), "CVE-2026-33816")

	// CVSS 3.1 vector becomes a CVSS_V3 severity.
	require.Len(t, record.GetSeverity(), 1)
	require.Equal(t, v1.Severity_CVSS_V3, record.GetSeverity()[0].GetType())
	require.Contains(t, record.GetSeverity()[0].GetScore(), "CVSS:3.1/")

	// Advisory + web references.
	require.NotEmpty(t, record.GetReferences())
	require.Equal(t, v1.Reference_ADVISORY, record.GetReferences()[0].GetType())

	// Affected package + reconstructed range up to the fix.
	require.Len(t, record.GetAffected(), 1)
	affected := record.GetAffected()[0]
	require.Equal(t, "Go", affected.GetPackage().GetEcosystem())
	require.Equal(t, "pkg:golang/github.com/jackc/pgx/v5@v5.8.0", affected.GetPackage().GetPurl())
	require.Equal(t, []string{"v5.8.0"}, affected.GetVersions())
	events := affected.GetRanges()[0].GetEvents()
	require.Equal(t, "0", events[0].GetIntroduced())
	require.Equal(t, "5.9.0", events[1].GetFixed())

	// database_specific carries grype extras.
	db := record.GetDatabaseSpecific().AsMap()
	require.Equal(t, "Critical", db["severity"])
	require.Equal(t, "fixed", db["fix_state"])
	require.Contains(t, db, "risk")
	require.Contains(t, db, "cvss_scores")
}

func TestToOSVDeterministic(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/grype.json")
	require.NoError(t, err)
	doc, err := Parse(data)
	require.NoError(t, err)

	first, err := doc.ToOSV()
	require.NoError(t, err)
	second, err := doc.ToOSV()
	require.NoError(t, err)

	firstJSON, err := protojson.Marshal(first)
	require.NoError(t, err)
	secondJSON, err := protojson.Marshal(second)
	require.NoError(t, err)
	require.JSONEq(t, string(firstJSON), string(secondJSON))
}

func findRecord(results *osv.Results, id string) *osv.Record {
	for _, res := range results.GetResults() {
		for _, pkg := range res.GetPackages() {
			for _, vuln := range pkg.GetVulnerabilities() {
				if vuln.GetId() == id {
					return vuln
				}
			}
		}
	}
	return nil
}
