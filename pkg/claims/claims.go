// Package claims contains the provider-neutral JSON claim value type used at
// trusted Dex boundaries.
package claims

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// JSONClaims contains JSON values for approved custom claims. Values are kept
// as raw JSON so numbers and arrays retain their original JSON types.
type JSONClaims map[string]json.RawMessage

const (
	DefaultMaxStringLength = 256
	DefaultMaxArraySize    = 32
)

// New returns an initialized, empty claim map.
func New() JSONClaims {
	return make(JSONClaims)
}

// Clone returns a deep copy of the claim map and its values.
func (c JSONClaims) Clone() JSONClaims {
	clone := New()
	for name, value := range c {
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, value); err == nil {
			clone[name] = append(json.RawMessage(nil), compacted.Bytes()...)
			continue
		}
		clone[name] = append(json.RawMessage(nil), value...)
	}
	return clone
}

// IsEmpty reports whether the map contains no claims.
func (c JSONClaims) IsEmpty() bool {
	return len(c) == 0
}

// ValidateScalarOrArray validates the bounded JSON value contract used by
// enrichment. Objects and nested arrays are intentionally excluded.
func ValidateScalarOrArray(value json.RawMessage, maxStringLength, maxArrayLength int) error {
	value = bytes.TrimSpace(value)
	if len(value) == 0 {
		return fmt.Errorf("value is empty")
	}

	var decoded interface{}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("decode value: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("value contains more than one JSON value")
	}

	switch typed := decoded.(type) {
	case string:
		return validateString(typed, maxStringLength)
	case bool:
		return nil
	case json.Number:
		return validateNumber(typed)
	case []interface{}:
		if len(typed) > maxArrayLength {
			return fmt.Errorf("array has %d values, maximum is %d", len(typed), maxArrayLength)
		}
		for _, item := range typed {
			switch item := item.(type) {
			case string:
				if err := validateString(item, maxStringLength); err != nil {
					return err
				}
			case bool:
			case json.Number:
				if err := validateNumber(item); err != nil {
					return err
				}
			default:
				return fmt.Errorf("arrays may contain only strings, booleans, or numbers")
			}
		}
		return nil
	default:
		return fmt.Errorf("value must be a string, boolean, number, or scalar array")
	}
}

func validateString(value string, maxLength int) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("string is not valid UTF-8")
	}
	if maxLength >= 0 && len([]rune(value)) > maxLength {
		return fmt.Errorf("string has %d characters, maximum is %d", len([]rune(value)), maxLength)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("string contains a control character")
		}
	}
	return nil
}

func validateNumber(value json.Number) error {
	float, err := strconv.ParseFloat(string(value), 64)
	if err != nil || math.IsNaN(float) || math.IsInf(float, 0) {
		return fmt.Errorf("number is not finite")
	}
	return nil
}

// String returns a JSON string value suitable for an approved claim.
func String(value string) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

// Strings returns a JSON string-array value suitable for an approved claim.
func Strings(values []string) json.RawMessage {
	encoded, _ := json.Marshal(values)
	return encoded
}

// Bool returns a JSON boolean value suitable for an approved claim.
func Bool(value bool) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}
