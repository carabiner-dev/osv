// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package osv

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"
)

type Parser struct{}

// NewParser returns a new OSV parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseFeedFromStream returns a feed object prased from the data read from r.
func (p *Parser) ParseRestultsFromStream(r io.Reader) (*Results, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	return p.ParseResults(data)
}

// ParseFeedFromStream returns a feed object prased from the data read from r.
func (p *Parser) ParseResults(data []byte) (*Results, error) {
	r := &Results{}
	pj := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
	if err := pj.Unmarshal(data, r); err != nil {
		return nil, fmt.Errorf("unmarshaling results: %w", err)
	}
	return r, nil
}
