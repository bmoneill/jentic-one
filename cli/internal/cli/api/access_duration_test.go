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

func TestParseIdleLimit(t *testing.T) {
	if got, err := parseIdleLimit("14d"); err != nil || got != 14*86400 {
		t.Errorf("parseIdleLimit(14d) = %d, %v", got, err)
	}
	for _, in := range []string{"12h", "23h", "1000d"} {
		if _, err := parseIdleLimit(in); err == nil {
			t.Errorf("parseIdleLimit(%q) succeeded; want an error", in)
		}
	}
}
