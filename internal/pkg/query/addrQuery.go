package query

import (
	"fmt"
	"net"
	"sort"

	cbor "github.com/britram/borat"

	"github.com/netsec-ethz/rains/internal/pkg/object"
)

//Address contains information about the address query
type Address struct {
	SubjectAddr *net.IPNet
	Context     string
	Types       []object.Type
	Expiration  int64 //Unix seconds
	Options     []Option
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (q *Address) UnmarshalMap(m map[int]interface{}) error {
	//FIXME encode subject addr as in the draft
	_, q.SubjectAddr, _ = net.ParseCIDR(m[8].(string))
	q.Context = m[6].(string)
	q.Types = make([]object.Type, 0)
	if types, ok := m[10]; ok {
		for _, qt := range types.([]interface{}) {
			q.Types = append(q.Types, object.Type(qt.(int)))
		}
	}
	q.Expiration = int64(m[12].(int))
	q.Options = make([]Option, 0)
	if opts, ok := m[13]; ok {
		for _, opt := range opts.([]interface{}) {
			q.Options = append(q.Options, Option(opt.(int)))
		}
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (q *Address) MarshalCBOR(w *cbor.CBORWriter) error {
	m := make(map[int]interface{})
	//FIXME encode subject addr as in the draft
	m[8] = q.SubjectAddr.String()
	m[6] = q.Context
	qtypes := make([]int, len(q.Types))
	for i, qtype := range q.Types {
		qtypes[i] = int(qtype)
	}
	m[10] = qtypes
	m[12] = q.Expiration
	qopts := make([]int, len(q.Options))
	for i, qopt := range q.Options {
		qopts[i] = int(qopt)
	}
	m[13] = qopts
	return w.WriteIntMap(m)
}

//GetContext returns q's context
func (q *Address) GetContext() string {
	return q.Context
}

//GetExpiration returns q's expiration
func (q *Address) GetExpiration() int64 {
	return q.Expiration
}

//ContainsOption returns true if the address query contains the given query option.
func (q *Address) ContainsOption(option Option) bool {
	return containsOption(option, q.Options)
}

//Sort sorts the content of the addressQuery lexicographically.
func (q *Address) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two addressQueries and returns 0 if they are equal, 1 if q is greater than
//query and -1 if q is smaller than query
func (q *Address) CompareTo(query *Address) int {
	if q.SubjectAddr.String() < query.SubjectAddr.String() {
		return -1
	} else if q.SubjectAddr.String() > query.SubjectAddr.String() {
		return 1
	} else if q.Context < query.Context {
		return -1
	} else if q.Context > query.Context {
		return 1
	} else if len(q.Types) < len(query.Types) {
		return -1
	} else if len(q.Types) > len(query.Types) {
		return 1
	}
	for i, o := range q.Types {
		if o < query.Types[i] {
			return -1
		} else if o > query.Types[i] {
			return 1
		}
	}
	if q.Expiration < query.Expiration {
		return -1
	} else if q.Expiration > query.Expiration {
		return 1
	} else if len(q.Options) < len(query.Options) {
		return -1
	} else if len(q.Options) > len(query.Options) {
		return 1
	}
	for i, o := range q.Options {
		if o < query.Options[i] {
			return -1
		} else if o > query.Options[i] {
			return 1
		}
	}
	return 0
}

//String implements Stringer interface
func (q *Address) String() string {
	if q == nil {
		return "AddressQuery:nil"
	}
	return fmt.Sprintf("AddressQuery:[SA=%s CTX=%s TYPE=%v EXP=%d OPT=%v]",
		q.SubjectAddr, q.Context, q.Types, q.Expiration, q.Options)
}
