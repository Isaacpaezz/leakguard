package menubar

import (
	"strings"
	"testing"
)

// S4: the Mac's first preferred language decides.
func TestParseLang(t *testing.T) {
	tests := []struct {
		in   string
		want Lang
	}{
		{"(\n    \"es-US\",\n    \"en-US\"\n)\n", Spanish},
		{"(\n    es,\n    en\n)\n", Spanish},
		{"es-US", Spanish},
		{"es", Spanish},
		{"es_VE", Spanish},
		{"ES-419", Spanish},
		{"(\n    \"en-GB\",\n    \"es-ES\"\n)\n", English},
		{"en-GB", English},
		{"et-EE", English},
		{"pt-BR", English},
		{"", English},
		{"()", English},
	}
	for _, tc := range tests {
		if got := ParseLang(tc.in); got != tc.want {
			t.Errorf("ParseLang(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// S4: every user-facing string exists in both languages, with the same
// placeholders.
func TestMessagesComplete(t *testing.T) {
	for m := Msg(0); m < msgCount; m++ {
		es, en := Spanish.Text(m), English.Text(m)
		if strings.TrimSpace(es) == "" || strings.TrimSpace(en) == "" {
			t.Errorf("message %d: es %q, en %q; want both", m, es, en)
			continue
		}
		if a, b := strings.Count(es, "%"), strings.Count(en, "%"); a != b {
			t.Errorf("message %d: %d placeholders in es, %d in en", m, a, b)
		}
	}
	if got := Lang("fr").Text(MsgMenuQuit); got != "Quit" {
		t.Errorf("unknown language reads %q, want English", got)
	}
	if got := Spanish.Text(msgCount); got != "" {
		t.Errorf("out-of-range message = %q, want empty", got)
	}
}

func TestList(t *testing.T) {
	tests := []struct {
		l     Lang
		names []string
		want  string
	}{
		{Spanish, nil, ""},
		{Spanish, []string{"A"}, "A"},
		{Spanish, []string{"A", "B"}, "A y B"},
		{English, []string{"A", "B", "C"}, "A, B and C"},
	}
	for _, tc := range tests {
		if got := tc.l.list(tc.names); got != tc.want {
			t.Errorf("%s list(%v) = %q, want %q", tc.l, tc.names, got, tc.want)
		}
	}
}
