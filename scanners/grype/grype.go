// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

// Package grype parses the JSON document emitted by Anchore's Grype scanner
// (`grype -o json`) and converts it into the OSV results format.
//
// Only the subset of the Grype document needed to build OSV records is modeled.
// The struct definitions are intentionally minimal mirrors of Grype's output;
// they are not imported from the grype module to avoid dragging in its very
// large dependency tree (grype pulls in syft, stereoscope, docker, ...). The
// committed testdata sample doubles as a fixture to catch upstream drift.
package grype

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/carabiner-dev/osv/go/osv"
	"github.com/carabiner-dev/osv/scanners/internal/purl"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Document is the top level of a Grype JSON report.
type Document struct {
	Matches    []Match     `json:"matches"`
	Source     *Source     `json:"source"`
	Descriptor *Descriptor `json:"descriptor"`
}

// Match pairs a detected vulnerability with the artifact it affects.
type Match struct {
	Vulnerability          Vulnerability          `json:"vulnerability"`
	RelatedVulnerabilities []RelatedVulnerability `json:"relatedVulnerabilities"`
	Artifact               Artifact               `json:"artifact"`
}

// Vulnerability is the primary matched vulnerability record.
type Vulnerability struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	URLs        []string `json:"urls"`
	Description string   `json:"description"`
	CVSS        []CVSS   `json:"cvss"`
	Fix         Fix      `json:"fix"`
	Risk        float64  `json:"risk"`
}

// RelatedVulnerability is an alias or closely related record (e.g. the CVE
// behind a matched GHSA).
type RelatedVulnerability struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	URLs        []string `json:"urls"`
	Description string   `json:"description"`
	CVSS        []CVSS   `json:"cvss"`
}

// CVSS is a single CVSS scoring for a vulnerability.
type CVSS struct {
	Source  string      `json:"source"`
	Type    string      `json:"type"`
	Version string      `json:"version"`
	Vector  string      `json:"vector"`
	Metrics CVSSMetrics `json:"metrics"`
}

// CVSSMetrics carries the numeric CVSS scores.
type CVSSMetrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

// Fix describes the fix state and fixed versions for a vulnerability.
type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

// Artifact is the package a match was found in.
type Artifact struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Language string `json:"language"`
	PURL     string `json:"purl"`
}

// Source identifies what was scanned. Target varies by source type (a string
// path for files, an object for images), so it is kept raw.
type Source struct {
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"`
}

// Descriptor carries scan metadata such as the scan timestamp.
type Descriptor struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

// Parse decodes a Grype JSON document.
func Parse(data []byte) (*Document, error) {
	doc := &Document{}
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("unmarshaling grype document: %w", err)
	}
	return doc, nil
}

// ToOSV converts the Grype document into the OSV results format. Grype emits a
// single flat list of matches for one source, so the output is one OSV result
// with findings grouped by the affected package.
func (d *Document) ToOSV() (*osv.Results, error) {
	results := &osv.Results{}
	if d.Descriptor != nil && d.Descriptor.Timestamp != "" {
		if ts, err := time.Parse(time.RFC3339, d.Descriptor.Timestamp); err == nil {
			results.Date = timestamppb.New(ts)
		}
	}

	if len(d.Matches) == 0 {
		return results, nil
	}

	osvResult := &osv.Result{Source: d.sourceInfo()}

	// Preserve encounter order so the output is deterministic.
	order := []string{}
	byPackage := map[string]*osv.Result_Package{}
	for i := range d.Matches {
		match := &d.Matches[i]
		record, err := matchToRecord(match)
		if err != nil {
			return nil, err
		}

		key := match.Artifact.Name + "@" + match.Artifact.Version
		pkg, ok := byPackage[key]
		if !ok {
			pkg = &osv.Result_Package{
				Package: &osv.Result_Package_Info{
					Name:      match.Artifact.Name,
					Version:   match.Artifact.Version,
					Ecosystem: purl.Ecosystem(match.Artifact.PURL, match.Artifact.Language),
				},
			}
			byPackage[key] = pkg
			order = append(order, key)
		}
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, record)
	}

	for _, key := range order {
		osvResult.Packages = append(osvResult.Packages, byPackage[key])
	}
	results.Results = []*osv.Result{osvResult}
	return results, nil
}

// matchToRecord maps a single Grype match to an OSV record.
func matchToRecord(match *Match) (*osv.Record, error) {
	vuln := &match.Vulnerability
	record := &osv.Record{
		SchemaVersion: osv.Version,
		Id:            vuln.ID,
		Details:       vuln.Description,
	}

	// Related vulnerabilities are the aliases (e.g. the CVE behind a GHSA).
	for i := range match.RelatedVulnerabilities {
		rel := &match.RelatedVulnerabilities[i]
		if rel.ID != "" && rel.ID != vuln.ID {
			record.Aliases = append(record.Aliases, rel.ID)
		}
	}

	if vuln.DataSource != "" {
		record.References = append(record.References, &osv.Reference{Type: "ADVISORY", Url: vuln.DataSource})
	}
	for _, url := range vuln.URLs {
		record.References = append(record.References, &osv.Reference{Type: "WEB", Url: url})
	}

	for i := range vuln.CVSS {
		cvss := &vuln.CVSS[i]
		if cvss.Vector != "" {
			record.Severity = append(record.Severity, &osv.Severity{Type: cvssMethod(cvss.Version), Score: cvss.Vector})
		}
	}

	affected := &osv.Affected{
		Package: &osv.Package{
			Name:      match.Artifact.Name,
			Purl:      match.Artifact.PURL,
			Ecosystem: purl.Ecosystem(match.Artifact.PURL, match.Artifact.Language),
		},
	}
	if match.Artifact.Version != "" {
		affected.Versions = []string{match.Artifact.Version}
	}
	// Grype reports the fixed version(s) rather than the full affected range,
	// so the range is a reconstruction: everything up to the first fix.
	events := []*osv.Range_Event{{Introduced: "0"}}
	if strings.EqualFold(vuln.Fix.State, "fixed") && len(vuln.Fix.Versions) > 0 {
		events = append(events, &osv.Range_Event{Fixed: vuln.Fix.Versions[0]})
	}
	affected.Ranges = []*osv.Range{{Type: "ECOSYSTEM", Events: events}}
	record.Affected = []*osv.Affected{affected}

	dbSpecific, err := databaseSpecific(vuln)
	if err != nil {
		return nil, err
	}
	record.DatabaseSpecific = dbSpecific

	return record, nil
}

// databaseSpecific packs the Grype fields that have no first-class OSV home
// (string severity, namespace, fix state/versions, risk, numeric CVSS scores)
// into the database_specific blob.
func databaseSpecific(vuln *Vulnerability) (*structpb.Struct, error) {
	fields := map[string]any{}
	if vuln.Severity != "" {
		fields["severity"] = vuln.Severity
	}
	if vuln.Namespace != "" {
		fields["namespace"] = vuln.Namespace
	}
	if vuln.Fix.State != "" {
		fields["fix_state"] = vuln.Fix.State
	}
	if len(vuln.Fix.Versions) > 0 {
		versions := make([]any, len(vuln.Fix.Versions))
		for i, v := range vuln.Fix.Versions {
			versions[i] = v
		}
		fields["fixed_versions"] = versions
	}
	if vuln.Risk != 0 {
		fields["risk"] = vuln.Risk
	}

	scores := []any{}
	for i := range vuln.CVSS {
		cvss := &vuln.CVSS[i]
		if cvss.Metrics.BaseScore != 0 {
			scores = append(scores, map[string]any{
				"version":    cvss.Version,
				"source":     cvss.Source,
				"base_score": cvss.Metrics.BaseScore,
			})
		}
	}
	if len(scores) > 0 {
		fields["cvss_scores"] = scores
	}

	if len(fields) == 0 {
		return nil, nil
	}
	st, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("building database_specific for %s: %w", vuln.ID, err)
	}
	return st, nil
}

// sourceInfo maps the Grype document source to an OSV result source. The target
// is only recorded when it is a plain string path (file/directory scans).
func (d *Document) sourceInfo() *osv.Result_Source {
	if d.Source == nil {
		return nil
	}
	source := &osv.Result_Source{Type: d.Source.Type}
	var path string
	if err := json.Unmarshal(d.Source.Target, &path); err == nil {
		source.Path = path
	}
	return source
}

// cvssMethod maps a CVSS version string to the OSV severity method.
func cvssMethod(version string) string {
	switch {
	case strings.HasPrefix(version, "4"):
		return "CVSS_V4"
	case strings.HasPrefix(version, "2"):
		return "CVSS_V2"
	default:
		return "CVSS_V3"
	}
}
