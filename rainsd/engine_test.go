package rainsd

import (
	"reflect"
	"testing"
)

func TestGetZoneAndName(t *testing.T) {
	testTable := []struct {
		in   string
		want []zoneAndName
	}{
		{
			in: ".",
			want: []zoneAndName{
				zoneAndName{
					name: "",
					zone: ".",
				},
			},
		},
		{
			in: "ch.",
			want: []zoneAndName{
				zoneAndName{
					name: "ch",
					zone: ".",
				},
			},
		},
		{
			in: "example.ch.",
			want: []zoneAndName{
				zoneAndName{
					name: "example",
					zone: "ch.",
				},
			},
		},
	}
	for i, testcase := range testTable {
		got := getZoneAndName(testcase.in)
		if !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("case %d: got: %v, want %v", i, got, testcase.want)
		}
	}
}
