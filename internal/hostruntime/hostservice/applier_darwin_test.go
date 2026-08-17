//go:build darwin

package hostservice

import "testing"

func TestParseLiveSleepDisabled(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   int
		ok     bool
	}{
		{
			name: "applied",
			output: `Currently in use:
 SleepDisabled		1
 Sleep On Power Button 1
 womp                 0`,
			want: 1,
			ok:   true,
		},
		{
			name: "not applied",
			output: `Currently in use:
 Sleep On Power Button 1
 womp                 0`,
			ok: false,
		},
		{
			name:   "invalid value",
			output: "SleepDisabled\t2",
			ok:     false,
		},
		{
			name:   "tolerates surrounding whitespace",
			output: "   SleepDisabled   0   ",
			want:   0,
			ok:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, ok := parseLiveSleepDisabled(test.output)
			if ok != test.ok || ok && value != test.want {
				t.Fatalf("parseLiveSleepDisabled(%q) = (%d, %v), want (%d, %v)", test.output, value, ok, test.want, test.ok)
			}
		})
	}
}
