// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package vulns

import (
	"testing"
	"time"

	"github.com/carabiner-dev/osv/go/osv"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func sampleResults(t *testing.T) *osv.Results {
	t.Helper()
	db, err := structpb.NewStruct(map[string]any{"severity": "CRITICAL"})
	require.NoError(t, err)
	return &osv.Results{
		Date: timestamppb.New(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)),
		Results: []*osv.Result{
			{
				Source: &osv.Result_Source{Path: "go.mod", Type: "lockfile"},
				Packages: []*osv.Result_Package{
					{
						Package: &osv.Result_Package_Info{
							Name:      "github.com/example/pkg",
							Version:   "1.2.0",
							Ecosystem: "Go",
						},
						Vulnerabilities: []*osv.Record{
							{
								Id:      "GHSA-xxxx-yyyy-zzzz",
								Summary: "example vulnerability",
								Aliases: []string{"CVE-2026-0001"},
								Severity: []*osv.Severity{
									{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
								},
								Affected: []*osv.Affected{
									{
										Package: &osv.Package{Name: "github.com/example/pkg", Purl: "pkg:golang/github.com/example/pkg@1.2.0", Ecosystem: "Go"},
										Ranges: []*osv.Range{
											{Type: "ECOSYSTEM", Events: []*osv.Range_Event{{Introduced: "0"}, {Fixed: "1.3.0"}}},
										},
									},
								},
								DatabaseSpecific: db,
							},
						},
					},
				},
			},
		},
	}
}

func TestFromResults(t *testing.T) {
	t.Parallel()

	predicate, err := FromResults(sampleResults(t), "https://trivy.dev")
	require.NoError(t, err)
	require.NotNil(t, predicate)

	require.Equal(t, "https://trivy.dev", predicate.GetScanner().GetUri())
	require.NotNil(t, predicate.GetMetadata().GetScanStartedOn())
	require.NotNil(t, predicate.GetMetadata().GetScanFinishedOn())

	require.Len(t, predicate.GetScanner().GetResult(), 1)
	result := predicate.GetScanner().GetResult()[0]
	require.Equal(t, "GHSA-xxxx-yyyy-zzzz", result.GetId())

	require.Len(t, result.GetSeverity(), 1)
	require.Equal(t, "CVSS_V3", result.GetSeverity()[0].GetMethod())
	require.Contains(t, result.GetSeverity()[0].GetScore(), "CVSS:3.1/")

	require.Len(t, result.GetAnnotations(), 1)
	annotation := result.GetAnnotations()[0].AsMap()
	require.Equal(t, "github.com/example/pkg", annotation["package"])
	require.Equal(t, "1.2.0", annotation["installed_version"])
	require.Equal(t, "Go", annotation["ecosystem"])
	require.Equal(t, "pkg:golang/github.com/example/pkg@1.2.0", annotation["purl"])
	require.Equal(t, "1.3.0", annotation["fixed_version"])
	require.Equal(t, "CRITICAL", annotation["severity"])
	require.Equal(t, "example vulnerability", annotation["summary"])
	require.Equal(t, "go.mod", annotation["source"])
	require.Contains(t, annotation["aliases"], "CVE-2026-0001")
}

func TestFromResultsEmpty(t *testing.T) {
	t.Parallel()

	predicate, err := FromResults(&osv.Results{}, "https://trivy.dev")
	require.NoError(t, err)
	require.NotNil(t, predicate)
	require.Empty(t, predicate.GetScanner().GetResult())
	require.Nil(t, predicate.GetMetadata().GetScanStartedOn())
}
