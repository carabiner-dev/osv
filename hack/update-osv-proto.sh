#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
#
# Regenerates the OSV record definition from the upstream ossf/osv-schema proto
# at the pinned version below, repointing its go_package to this module, then
# runs `buf generate`. Run this to bump the OSV schema:
#
#     hack/update-osv-proto.sh
#
set -euo pipefail

# The upstream ossf/osv-schema tag to vendor the record proto from.
OSV_SCHEMA_VERSION="v1.8.0"

DEST="proto/osv/v1/vulnerability.proto"
URL="https://raw.githubusercontent.com/ossf/osv-schema/${OSV_SCHEMA_VERSION}/proto/vulnerability.proto"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

tmp="$(mktemp)"
{
	echo "// Code generated from ossf/osv-schema ${OSV_SCHEMA_VERSION}; DO NOT EDIT."
	echo "// Regenerate with hack/update-osv-proto.sh"
	echo
	curl -fsSL "${URL}" |
		sed 's#option go_package = "github.com/ossf/osv-schema/bindings/go/osvschema";#option go_package = "github.com/carabiner-dev/osv/go/osv/v1";#'
} >"${tmp}"
mv "${tmp}" "${DEST}"

buf generate

echo "Updated ${DEST} from ossf/osv-schema ${OSV_SCHEMA_VERSION} and regenerated Go bindings."
