package ui

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStylesProvideResponsiveAccessibleLayoutPrimitives(t *testing.T) {
	for _, contract := range []string{
		".page-shell", ".card", ".field-grid", ".token-field", ".result",
		"focus-visible", "overflow-wrap: anywhere", "@media (max-width: 720px)",
		"@media (prefers-reduced-motion: reduce)", "button:not(:disabled):hover",
		"button.secondary:not(:disabled):hover", "outline: 3px solid #4f46e5",
	} {
		require.Contains(t, Styles, contract)
	}
}
