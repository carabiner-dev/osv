# OSV Tools and Protocol Buffer Definitions

This repository contains tools, libraries and protocol buffer definitions to work
with the [Open Source Vulnerabilities format](https://github.com/ossf/osv-schema).

## Using the Libraries

This repository contains libraries to read OSV data generated from the protocol
buffer definitions. For now we are only generating go modules, read below if you
need others.

### Go

The go module can be imported as:

```
go get github.com/carabiner-dev/osv
```

The main osv module maintains type aliases to all the major types defined in
the protocol buffers definition. This means that this:

```golang
package main

import(
    "github.com/carabiner-dev/osv/go/osv"
)
var r = osv.Record{}
```

will always give you a record of the latest support version. If you want a more
deterministic behavior, you can always use the versioned types:

```golang
package main

import(
    osv "github.com/carabiner-dev/osv/go/osv/v1_6_7"
)

var r = osv.Record{} // This will always be a v1.6.7 record
```

The main module offers a simple parser that can parse results sets:

```golang
package main

import(
    "github.com/carabiner-dev/osv/go/osv"
)

func main() {
    f, err := os.Open("osv-data.json")
    if err != nil {
        os.Exit(1)
    }

    // Create new parser
    parser := osv.NewParser()

    // Parse the OSV data
    results, err := parse.ParseRestultsFromStream(f)
}
```

### Other Languages

There are currently no plans to generate code for other languages but feel 
free to file an issue or open a PR if you need them.

## Regenerating the Code

This repository generates code for the protos it owns — the results wrapper
(`proto/osv/osv.proto`) and the frozen v1.6.7 record (`proto/osv/v1.6.7.proto`).
The current OSV record definition is **not** generated here: `go/osv/v1` is a
set of aliases for the upstream
[`github.com/ossf/osv-schema/bindings/go`](https://github.com/ossf/osv-schema)
module, and `proto/osv/vulnerability.proto` is a vendored copy kept purely as a
`buf` import so `osv.proto` can reference `osv.Vulnerability`.

That split is deliberate. Generating our own copy of the upstream record proto
registers the same proto file and message names twice, and the global protobuf
registry rejects the duplicate with a panic during initialization — any binary
combining this module with a consumer of the upstream bindings (Google's OSV
Scanner, among others) then fails to start.

[Install the latest version of the `buf` CLI](https://buf.build/docs/installation/)
and regenerate — including refreshing the vendored import — with:

```
hack/update-osv-proto.sh
```

Bumping the OSV schema means bumping `OSV_SCHEMA_VERSION` in that script and the
`github.com/ossf/osv-schema/bindings/go` requirement in `go.mod` together. Note
that a plain `buf generate` is **not** equivalent: it would generate the vendored
import as well and reintroduce the duplicate registration.
