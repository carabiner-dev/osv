// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

// Package trivy parses the JSON report emitted by Aqua Security's Trivy
// scanner (`trivy ... -f json`) and converts it into the OSV results format.
//
// Only the subset of the Trivy report needed to build OSV records is modeled.
// The struct definitions are intentionally minimal mirrors of Trivy's output;
// they are not imported from the trivy module to avoid dragging in its very
// large dependency tree. The committed testdata sample doubles as a fixture to
// catch upstream format drift.
package trivy

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/osv/go/osv"
	v1 "github.com/carabiner-dev/osv/go/osv/v1"
	"github.com/carabiner-dev/osv/scanners/internal/purl"
)

// Report is the top level of a Trivy JSON report.
type Report struct {
	SchemaVersion int       `json:"SchemaVersion"`
	CreatedAt     time.Time `json:"CreatedAt"`
	ArtifactName  string    `json:"ArtifactName"`
	ArtifactType  string    `json:"ArtifactType"`
	Results       []Result  `json:"Results"`
}

// Result groups the findings for a single scan target (an image layer, a
// lockfile, an OS package database, etc).
type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// Vulnerability is a single detected vulnerability affecting a package.
type Vulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgName          string          `json:"PkgName"`
	PkgIdentifier    PkgIdentifier   `json:"PkgIdentifier"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Status           string          `json:"Status"`
	SeveritySource   string          `json:"SeveritySource"`
	PrimaryURL       string          `json:"PrimaryURL"`
	DataSource       *DataSource     `json:"DataSource"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	Severity         string          `json:"Severity"`
	CweIDs           []string        `json:"CweIDs"`
	CVSS             map[string]CVSS `json:"CVSS"`
	References       []string        `json:"References"`
	PublishedDate    *time.Time      `json:"PublishedDate"`
	LastModifiedDate *time.Time      `json:"LastModifiedDate"`
}

// PkgIdentifier carries the package URL. Trivy marshals the PURL as a string.
type PkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

// CVSS is a single vendor's scoring for a vulnerability.
type CVSS struct {
	V2Vector  string  `json:"V2Vector"`
	V3Vector  string  `json:"V3Vector"`
	V40Vector string  `json:"V40Vector"`
	V2Score   float64 `json:"V2Score"`
	V3Score   float64 `json:"V3Score"`
	V40Score  float64 `json:"V40Score"`
}

// DataSource identifies the advisory database a finding came from.
type DataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

// Parse decodes a Trivy JSON report.
func Parse(data []byte) (*Report, error) {
	report := &Report{}
	if err := json.Unmarshal(data, report); err != nil {
		return nil, fmt.Errorf("unmarshaling trivy report: %w", err)
	}
	return report, nil
}

// ToOSV converts the Trivy report into the OSV results format. Each Trivy
// result becomes an OSV result keyed by its target, with findings grouped by
// the affected package.
func (r *Report) ToOSV() (*osv.Results, error) {
	results := &osv.Results{}
	if !r.CreatedAt.IsZero() {
		results.Date = timestamppb.New(r.CreatedAt)
	}

	for i := range r.Results {
		tr := &r.Results[i]
		if len(tr.Vulnerabilities) == 0 {
			continue
		}

		osvResult := &osv.Result{
			Source: &osv.Result_Source{Path: tr.Target, Type: tr.Class},
		}

		// Preserve encounter order so the output is deterministic.
		order := []string{}
		byPackage := map[string]*osv.Result_Package{}
		for j := range tr.Vulnerabilities {
			vuln := &tr.Vulnerabilities[j]
			record, err := vulnToRecord(vuln, tr.Type)
			if err != nil {
				return nil, err
			}

			key := vuln.PkgName + "@" + vuln.InstalledVersion
			pkg, ok := byPackage[key]
			if !ok {
				pkg = &osv.Result_Package{
					Package: &osv.Result_Package_Info{
						Name:      vuln.PkgName,
						Version:   vuln.InstalledVersion,
						Ecosystem: purl.Ecosystem(vuln.PkgIdentifier.PURL, tr.Type),
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
		results.Results = append(results.Results, osvResult)
	}

	return results, nil
}

// vulnToRecord maps a single Trivy vulnerability to an OSV record.
func vulnToRecord(vuln *Vulnerability, trivyType string) (*osv.Record, error) {
	record := &osv.Record{
		SchemaVersion: osv.Version,
		Id:            vuln.VulnerabilityID,
		Summary:       vuln.Title,
		Details:       vuln.Description,
	}

	if vuln.PublishedDate != nil {
		record.Published = timestamppb.New(*vuln.PublishedDate)
	}
	if vuln.LastModifiedDate != nil {
		record.Modified = timestamppb.New(*vuln.LastModifiedDate)
	}

	for _, url := range vuln.References {
		record.References = append(record.References, &osv.Reference{Type: v1.Reference_WEB, Url: url})
	}

	// Emit a severity entry per vendor/method. Iterate vendors in sorted order
	// so the output is stable across runs.
	for _, vendor := range sortedKeys(vuln.CVSS) {
		cvss := vuln.CVSS[vendor]
		if cvss.V40Vector != "" {
			record.Severity = append(record.Severity, &osv.Severity{Type: v1.Severity_CVSS_V4, Score: cvss.V40Vector})
		}
		if cvss.V3Vector != "" {
			record.Severity = append(record.Severity, &osv.Severity{Type: v1.Severity_CVSS_V3, Score: cvss.V3Vector})
		}
		if cvss.V2Vector != "" {
			record.Severity = append(record.Severity, &osv.Severity{Type: v1.Severity_CVSS_V2, Score: cvss.V2Vector})
		}
	}

	affected := &osv.Affected{
		Package: &osv.Package{
			Name:      vuln.PkgName,
			Purl:      vuln.PkgIdentifier.PURL,
			Ecosystem: purl.Ecosystem(vuln.PkgIdentifier.PURL, trivyType),
		},
	}
	if vuln.InstalledVersion != "" {
		affected.Versions = []string{vuln.InstalledVersion}
	}
	// Trivy reports a single installed/fixed pair rather than the full affected
	// range, so the range is a reconstruction: everything up to the fix.
	events := []*osv.Range_Event{{Introduced: "0"}}
	if vuln.FixedVersion != "" {
		events = append(events, &osv.Range_Event{Fixed: vuln.FixedVersion})
	}
	affected.Ranges = []*osv.Range{{Type: v1.Range_ECOSYSTEM, Events: events}}
	record.Affected = []*osv.Affected{affected}

	dbSpecific, err := databaseSpecific(vuln)
	if err != nil {
		return nil, err
	}
	record.DatabaseSpecific = dbSpecific

	return record, nil
}

// databaseSpecific packs the Trivy fields that have no first-class OSV home
// (string severity, CWEs, numeric CVSS scores) into the database_specific blob.
func databaseSpecific(vuln *Vulnerability) (*structpb.Struct, error) {
	fields := map[string]any{}
	if vuln.Severity != "" {
		fields["severity"] = vuln.Severity
	}
	if vuln.PrimaryURL != "" {
		fields["primary_url"] = vuln.PrimaryURL
	}
	if len(vuln.CweIDs) > 0 {
		cwes := make([]any, len(vuln.CweIDs))
		for i, id := range vuln.CweIDs {
			cwes[i] = id
		}
		fields["cwe_ids"] = cwes
	}

	scores := map[string]any{}
	for _, vendor := range sortedKeys(vuln.CVSS) {
		cvss := vuln.CVSS[vendor]
		entry := map[string]any{}
		if cvss.V2Score != 0 {
			entry["v2_score"] = cvss.V2Score
		}
		if cvss.V3Score != 0 {
			entry["v3_score"] = cvss.V3Score
		}
		if cvss.V40Score != 0 {
			entry["v4_score"] = cvss.V40Score
		}
		if len(entry) > 0 {
			scores[vendor] = entry
		}
	}
	if len(scores) > 0 {
		fields["cvss"] = scores
	}

	if len(fields) == 0 {
		return nil, nil
	}
	st, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("building database_specific for %s: %w", vuln.VulnerabilityID, err)
	}
	return st, nil
}

// sortedKeys returns the keys of the CVSS map in deterministic order.
func sortedKeys(m map[string]CVSS) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
