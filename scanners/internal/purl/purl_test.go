// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package purl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEcosystem(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		purl     string
		fallback string
		expected string
	}{
		{"golang", "pkg:golang/github.com/x/y@1.2.0", "fb", "Go"},
		{"pypi", "pkg:pypi/requests@2.0", "fb", "PyPI"},
		{"cargo", "pkg:cargo/serde@1", "fb", "crates.io"},
		{"deb", "pkg:deb/debian/bash@5", "fb", "Debian"},
		{"type-only-no-version", "pkg:golang", "fb", "Go"},
		{"uppercase-type", "pkg:GOLANG/x@1", "fb", "Go"},
		{"unknown-type-falls-back", "pkg:brandnew/x@1", "fb", "fb"},
		{"no-pkg-prefix-falls-back", "not-a-purl", "gobinary", "gobinary"},
		{"empty-purl-falls-back", "", "os-pkgs", "os-pkgs"},
		{"bare-pkg-prefix-falls-back", "pkg:", "fb", "fb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, Ecosystem(tc.purl, tc.fallback))
		})
	}
}
