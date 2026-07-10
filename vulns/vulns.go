// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

// Package vulns projects the OSV results format onto the in-toto vulns/v0.2
// predicate (https://in-toto.io/attestation/vulns/v0.2).
//
// The vulns/v0.2 predicate is a thin, scanner-agnostic report: each result is
// just a vulnerability id plus severity scores, with a free-form annotations
// blob for everything else. The richer OSV data (package, purl, fixed version,
// aliases) is preserved in the annotations so it is not lost in the projection.
package vulns

import (
	"fmt"

	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-dev/osv/go/osv"
)

// FromResults projects an OSV results set onto a vulns/v0.2 predicate. The
// scannerURI identifies the scanner that produced the results (the OSV format
// does not carry scanner identity, so the caller must supply it).
func FromResults(results *osv.Results, scannerURI string) (*v02.Vulns, error) {
	predicate := &v02.Vulns{
		Scanner: &v02.Scanner{
			Uri:    scannerURI,
			Result: []*v02.Result{},
		},
		Metadata: &v02.ScanMetadata{},
	}

	// The OSV results carry a single date; use it for both scan endpoints.
	if date := results.GetDate(); date != nil {
		predicate.Metadata.ScanStartedOn = date
		predicate.Metadata.ScanFinishedOn = date
	}

	for _, result := range results.GetResults() {
		sourcePath := result.GetSource().GetPath()
		for _, pkg := range result.GetPackages() {
			info := pkg.GetPackage()
			for _, record := range pkg.GetVulnerabilities() {
				vulnResult := &v02.Result{Id: record.GetId()}

				for _, severity := range record.GetSeverity() {
					vulnResult.Severity = append(vulnResult.Severity, &v02.Result_Severity{
						Method: severity.GetType().String(),
						Score:  severity.GetScore(),
					})
				}

				annotation, err := buildAnnotation(record, info, sourcePath)
				if err != nil {
					return nil, err
				}
				if annotation != nil {
					vulnResult.Annotations = append(vulnResult.Annotations, annotation)
				}

				predicate.Scanner.Result = append(predicate.Scanner.Result, vulnResult)
			}
		}
	}

	return predicate, nil
}

// buildAnnotation packs the OSV per-finding detail that vulns/v0.2 has no
// first-class field for (package identity, purl, fixed version, aliases,
// summary, source, string severity) into a single annotation struct.
func buildAnnotation(record *osv.Record, info *osv.Result_Package_Info, sourcePath string) (*structpb.Struct, error) {
	fields := map[string]any{}

	if info.GetName() != "" {
		fields["package"] = info.GetName()
	}
	if info.GetVersion() != "" {
		fields["installed_version"] = info.GetVersion()
	}
	if info.GetEcosystem() != "" {
		fields["ecosystem"] = info.GetEcosystem()
	}
	if purl := recordPURL(record); purl != "" {
		fields["purl"] = purl
	}
	if fixed := fixedVersion(record); fixed != "" {
		fields["fixed_version"] = fixed
	}
	if aliases := record.GetAliases(); len(aliases) > 0 {
		values := make([]any, len(aliases))
		for i, alias := range aliases {
			values[i] = alias
		}
		fields["aliases"] = values
	}
	if summary := record.GetSummary(); summary != "" {
		fields["summary"] = summary
	}
	if sourcePath != "" {
		fields["source"] = sourcePath
	}
	// Surface the scanner's own severity label (e.g. "CRITICAL") when present;
	// vulns/v0.2 severity only carries quantitative CVSS scores.
	if db := record.GetDatabaseSpecific(); db != nil {
		if severity, ok := db.AsMap()["severity"].(string); ok && severity != "" {
			fields["severity"] = severity
		}
	}

	if len(fields) == 0 {
		return nil, nil
	}
	annotation, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("building annotation for %s: %w", record.GetId(), err)
	}
	return annotation, nil
}

// recordPURL returns the package URL of the record's first affected package.
func recordPURL(record *osv.Record) string {
	for _, affected := range record.GetAffected() {
		if purl := affected.GetPackage().GetPurl(); purl != "" {
			return purl
		}
	}
	return ""
}

// fixedVersion returns the first fixed version found in the record's affected
// ranges, if any.
func fixedVersion(record *osv.Record) string {
	for _, affected := range record.GetAffected() {
		for _, rng := range affected.GetRanges() {
			for _, event := range rng.GetEvents() {
				if event.GetFixed() != "" {
					return event.GetFixed()
				}
			}
		}
	}
	return ""
}
