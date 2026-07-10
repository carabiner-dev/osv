// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

// Package purl holds helpers shared by the scanner converters for deriving
// OSV ecosystem names from package URLs.
package purl

import "strings"

// ecosystems maps a package URL type to the corresponding OSV ecosystem name.
var ecosystems = map[string]string{
	"golang":   "Go",
	"npm":      "npm",
	"pypi":     "PyPI",
	"maven":    "Maven",
	"cargo":    "crates.io",
	"gem":      "RubyGems",
	"nuget":    "NuGet",
	"composer": "Packagist",
	"deb":      "Debian",
	"apk":      "Alpine",
	"hex":      "Hex",
	"pub":      "Pub",
	"conan":    "ConanCenter",
}

// Ecosystem derives the OSV ecosystem from a package URL, falling back to the
// supplied value when the PURL type is unknown or the PURL is absent.
func Ecosystem(purl, fallback string) string {
	if rest, ok := strings.CutPrefix(purl, "pkg:"); ok {
		typ := rest
		if i := strings.IndexAny(rest, "/@"); i >= 0 {
			typ = rest[:i]
		}
		if eco, ok := ecosystems[strings.ToLower(typ)]; ok {
			return eco
		}
	}
	return fallback
}
