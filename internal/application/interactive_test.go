package application

import "testing"

func TestCollectSelectedValues(t *testing.T) {
	values := []string{"a", "b", "c"}
	selected := []bool{true, false, true}

	got := collectSelectedValues(values, selected)
	if len(got) != 2 {
		t.Fatalf("expected 2 selected values, got %d", len(got))
	}
	if got[0] != "a" || got[1] != "c" {
		t.Fatalf("unexpected selected values: %+v", got)
	}
}

func TestCollectSelectedValuesLengthMismatch(t *testing.T) {
	got := collectSelectedValues([]string{"a"}, []bool{})
	if got != nil {
		t.Fatalf("expected nil for length mismatch, got %+v", got)
	}
}
