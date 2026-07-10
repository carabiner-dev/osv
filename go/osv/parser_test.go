// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package osv

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRestultsFromStream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		path            string
		mustErr         bool
		validateResults func(*testing.T, *Results)
	}{
		{"osv-scanner-output", "testdata/osv-scnner-release.json", false, func(t *testing.T, res *Results) {
			t.Helper()
			require.NotNil(t, res)
			require.Len(t, res.GetResults(), 1)
			require.Len(t, res.GetResults()[0].GetPackages(), 4)
			require.Len(t, res.GetResults()[0].GetPackages()[0].GetVulnerabilities(), 4)
			require.Len(t, res.GetResults()[0].GetPackages()[0].GetVulnerabilities()[0].GetAffected(), 3)
			require.Equal(t, "GHSA-r9px-m959-cxf4", res.GetResults()[0].GetPackages()[0].GetVulnerabilities()[0].GetId())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parser := Parser{}
			f, err := os.Open(tc.path)
			require.NoError(t, err)
			feed, err := parser.ParseRestultsFromStream(f)
			if tc.mustErr {
				require.Error(t, err)
			}
			require.NoError(t, err)
			if tc.validateResults != nil {
				tc.validateResults(t, feed)
			}
		})
	}
}
