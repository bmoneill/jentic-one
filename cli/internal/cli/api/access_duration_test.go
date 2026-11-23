package api

import "testing"

func TestParseAccessDuration(t *testing.T) {
	for in, want := range map[string]int{"7d": 604800, "8h": 28800, "30m": 1800, "45s": 45, "3600": 3600, " 2D ": 172800, "999d": 999 * 86400} {
		got, err := parseAccessDuration(in)
		if err != nil || got != want {
			t.Errorf("parseAccessDuration(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0d", "1000d", "1w", "1.5d", "-1h", "d"} {
		if _, err := parseAccessDuration(in); err == nil {
			t.Errorf("parseAccessDuration(%q) succeeded; want an error", in)
		}
	}
}
