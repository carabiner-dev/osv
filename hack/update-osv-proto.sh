#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
#
# Refreshes the vendored copy of the upstream ossf/osv-schema record proto at
# the pinned version below and regenerates the Go bindings for the protos this
# module actually owns. Run this to bump the OSV schema:
#
#     hack/update-osv-proto.sh
#
# The vendored vulnerability.proto is an IMPORT ONLY: it is what `buf` compiles
# osv.proto's reference to osv.Vulnerability against, and nothing is generated
# from it. The Go type comes from the upstream bindings module, which is why its
# go_package is left pointing there.
#
# Generating our own copy of it — which this script used to do, by rewriting
# go_package — produces a second registration of the same proto file and message
# names. The global protobuf registry rejects that with a panic during
# initialization, so any binary combining this module with a consumer of the
# upstream bindings (Google's OSV Scanner, for one) fails to start. Keep the
# generation limited to the files this module owns.
set -euo pipefail

# The upstream ossf/osv-schema tag to vendor the record proto from. Keep the
# github.com/ossf/osv-schema/bindings/go requirement in go.mod in step with it.
OSV_SCHEMA_VERSION="v1.8.0"

DEST="proto/osv/vulnerability.proto"
URL="https://raw.githubusercontent.com/ossf/osv-schema/${OSV_SCHEMA_VERSION}/proto/vulnerability.proto"

# The protos this module owns, and the only ones generated from.
OWNED=(proto/osv/osv.proto proto/osv/v1.6.7.proto)

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

tmp="$(mktemp)"
{
	echo "// Vendored from ossf/osv-schema ${OSV_SCHEMA_VERSION} as a buf import; DO NOT EDIT."
	echo "// Nothing is generated from this file — the Go types come from the"
	echo "// github.com/ossf/osv-schema/bindings/go module. Refresh with hack/update-osv-proto.sh"
	echo
	curl -fsSL "${URL}"
} >"${tmp}"
mv "${tmp}" "${DEST}"

paths=()
for proto in "${OWNED[@]}"; do
	paths+=(--path "${proto}")
done
buf generate "${paths[@]}"

echo "Updated ${DEST} from ossf/osv-schema ${OSV_SCHEMA_VERSION} and regenerated Go bindings."
