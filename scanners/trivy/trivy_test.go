// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package trivy

import (
	"os"
	"testing"

	"github.com/carabiner-dev/osv/go/osv"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestToOSV(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/trivy.json")
	require.NoError(t, err)

	report, err := Parse(data)
	require.NoError(t, err)
	require.NotEmpty(t, report.Results)

	results, err := report.ToOSV()
	require.NoError(t, err)
	require.NotNil(t, results)
	require.NotNil(t, results.GetDate(), "report CreatedAt should populate results date")
	require.NotEmpty(t, results.GetResults())

	// Every OSV result must carry a source and at least one package.
	for _, res := range results.GetResults() {
		require.NotNil(t, res.GetSource())
		require.NotEmpty(t, res.GetPackages())
	}

	record := findRecord(results, "CVE-2025-21613")
	require.NotNil(t, record, "expected CVE-2025-21613 in the converted results")
	require.Equal(t, "go-git: argument injection via the URL field", record.GetSummary())
	require.NotEmpty(t, record.GetDetails())
	require.NotNil(t, record.GetPublished())

	// Severities come from the vendor-keyed CVSS map (ghsa + redhat V3 vectors).
	require.Len(t, record.GetSeverity(), 2)
	for _, sev := range record.GetSeverity() {
		require.Equal(t, "CVSS_V3", sev.GetType())
		require.Contains(t, sev.GetScore(), "CVSS:3.1/")
	}

	// Affected package + reconstructed range (introduced 0 .. fixed).
	require.Len(t, record.GetAffected(), 1)
	affected := record.GetAffected()[0]
	require.Equal(t, "Go", affected.GetPackage().GetEcosystem())
	require.Equal(t, "pkg:golang/github.com/go-git/go-git/v5@5.12.0", affected.GetPackage().GetPurl())
	require.Equal(t, []string{"5.12.0"}, affected.GetVersions())
	require.Len(t, affected.GetRanges(), 1)
	events := affected.GetRanges()[0].GetEvents()
	require.Equal(t, "0", events[0].GetIntroduced())
	require.Equal(t, "5.13.0", events[1].GetFixed())

	// database_specific carries the fields OSV has no first-class slot for.
	db := record.GetDatabaseSpecific().AsMap()
	require.Equal(t, "CRITICAL", db["severity"])
	require.Contains(t, db, "cwe_ids")
	require.Contains(t, db, "cvss")
}

func TestToOSVDeterministic(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/trivy.json")
	require.NoError(t, err)
	report, err := Parse(data)
	require.NoError(t, err)

	first, err := report.ToOSV()
	require.NoError(t, err)
	second, err := report.ToOSV()
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
