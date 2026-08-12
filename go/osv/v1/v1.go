// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

// Package v1 exposes the OSV record definition under the import path this
// module has always published it at.
//
// The definitions themselves come from the upstream ossf/osv-schema Go
// bindings; this package is nothing but aliases for them. It used to carry its
// own copy, generated from a vendored proto that declared the same proto
// package and message names as upstream. Two such copies cannot coexist in one
// binary: the global protobuf registry rejects the duplicate registration with
// a panic during initialization, which broke any program combining this module
// with a consumer of the upstream bindings — notably Google's OSV Scanner.
package v1

import (
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// The OSV record messages.
type (
	Affected = osvschema.Affected
	// Deprecated: mirrors the upstream deprecation of osv.Commit.
	Commit        = osvschema.Commit //nolint:staticcheck // the alias mirrors the upstream type, deprecation included
	Credit        = osvschema.Credit
	Event         = osvschema.Event
	Package       = osvschema.Package
	Range         = osvschema.Range
	Reference     = osvschema.Reference
	Severity      = osvschema.Severity
	Vulnerability = osvschema.Vulnerability
)

// The enumerations the record messages use.
type (
	Commit_RepoType = osvschema.Commit_RepoType //nolint:revive // the generated name is the API
	Credit_Type     = osvschema.Credit_Type     //nolint:revive // the generated name is the API
	Range_Type      = osvschema.Range_Type      //nolint:revive // the generated name is the API
	Reference_Type  = osvschema.Reference_Type  //nolint:revive // the generated name is the API
	Severity_Source = osvschema.Severity_Source //nolint:revive // the generated name is the API
	Severity_Type   = osvschema.Severity_Type   //nolint:revive // the generated name is the API
)

//nolint:revive // the generated names are the API
const (
	// Commit_RepoType values.
	Commit_UNSPECIFIED = osvschema.Commit_UNSPECIFIED
	Commit_GIT         = osvschema.Commit_GIT

	// Range_Type values.
	Range_UNSPECIFIED = osvschema.Range_UNSPECIFIED
	Range_GIT         = osvschema.Range_GIT
	Range_SEMVER      = osvschema.Range_SEMVER
	Range_ECOSYSTEM   = osvschema.Range_ECOSYSTEM

	// Severity_Type values.
	Severity_UNSPECIFIED = osvschema.Severity_UNSPECIFIED
	Severity_CVSS_V3     = osvschema.Severity_CVSS_V3
	Severity_CVSS_V2     = osvschema.Severity_CVSS_V2
	Severity_CVSS_V4     = osvschema.Severity_CVSS_V4
	Severity_Ubuntu      = osvschema.Severity_Ubuntu

	// Severity_Source values.
	Severity_SOURCE_UNSPECIFIED = osvschema.Severity_SOURCE_UNSPECIFIED
	Severity_NVD                = osvschema.Severity_NVD
	Severity_CNA                = osvschema.Severity_CNA
	Severity_SELF               = osvschema.Severity_SELF

	// Credit_Type values.
	Credit_UNSPECIFIED           = osvschema.Credit_UNSPECIFIED
	Credit_OTHER                 = osvschema.Credit_OTHER
	Credit_FINDER                = osvschema.Credit_FINDER
	Credit_REPORTER              = osvschema.Credit_REPORTER
	Credit_ANALYST               = osvschema.Credit_ANALYST
	Credit_COORDINATOR           = osvschema.Credit_COORDINATOR
	Credit_REMEDIATION_DEVELOPER = osvschema.Credit_REMEDIATION_DEVELOPER
	Credit_REMEDIATION_REVIEWER  = osvschema.Credit_REMEDIATION_REVIEWER
	Credit_REMEDIATION_VERIFIER  = osvschema.Credit_REMEDIATION_VERIFIER
	Credit_TOOL                  = osvschema.Credit_TOOL
	Credit_SPONSOR               = osvschema.Credit_SPONSOR

	// Reference_Type values.
	Reference_NONE       = osvschema.Reference_NONE
	Reference_ADVISORY   = osvschema.Reference_ADVISORY
	Reference_ARTICLE    = osvschema.Reference_ARTICLE
	Reference_DETECTION  = osvschema.Reference_DETECTION
	Reference_DISCUSSION = osvschema.Reference_DISCUSSION
	Reference_EVIDENCE   = osvschema.Reference_EVIDENCE
	Reference_FIX        = osvschema.Reference_FIX
	Reference_GIT        = osvschema.Reference_GIT
	Reference_INTRODUCED = osvschema.Reference_INTRODUCED
	Reference_PACKAGE    = osvschema.Reference_PACKAGE
	Reference_REPORT     = osvschema.Reference_REPORT
	Reference_WEB        = osvschema.Reference_WEB
)

// The enumeration name and value maps.
//
//nolint:revive // the generated names are the API
var (
	Commit_RepoType_name  = osvschema.Commit_RepoType_name
	Commit_RepoType_value = osvschema.Commit_RepoType_value

	Credit_Type_name  = osvschema.Credit_Type_name
	Credit_Type_value = osvschema.Credit_Type_value

	Range_Type_name  = osvschema.Range_Type_name
	Range_Type_value = osvschema.Range_Type_value

	Reference_Type_name  = osvschema.Reference_Type_name
	Reference_Type_value = osvschema.Reference_Type_value

	Severity_Source_name  = osvschema.Severity_Source_name
	Severity_Source_value = osvschema.Severity_Source_value

	Severity_Type_name  = osvschema.Severity_Type_name
	Severity_Type_value = osvschema.Severity_Type_value
)
