package cbor

import (
	"fmt"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/rainslib"
	"golang.org/x/crypto/ed25519"
)

var mapping = []struct {
	tag borat.CBORTag
	t   interface{}
}{
	{314, rainslib.PublicKey{}},
	{315, rainslib.ServiceInfo{}},
	{316, rainslib.ZoneSection{}},
	{317, rainslib.ShardSection{}},
	{318, rainslib.AssertionSection{}},
	{319, rainslib.Object{}},
	{320, uint8(0)},
	{321, rainslib.Signature{}},
	{322, string("")},
	{323, ed25519.PublicKey{}},
	{324, []byte{}},
	{325, rainslib.NotificationSection{}},
	{326, rainslib.ObjectType(0)},
	{327, rainslib.QuerySection{}},
	{328, rainslib.AddressQuerySection{}},
}

// ConfigureReader sets the appropriate tags in the registry for the provided reader.
func ConfigureReader(r *borat.CBORReader) error {
	for _, m := range mapping {
		if err := r.RegisterCBORTag(m.tag, m.t); err != nil {
			return fmt.Errorf("failed to register tag on reader: %v", err)
		}
	}
	return nil
}

// ConfigureWriter sets the appropriate tags in the registry for the provided writer.
func ConfigureWriter(w *borat.CBORWriter) error {
	for _, m := range mapping {
		if err := w.RegisterCBORTag(m.tag, m.t); err != nil {
			return fmt.Errorf("failed to register tag on writer: %v", err)
		}
	}
	return nil
}
