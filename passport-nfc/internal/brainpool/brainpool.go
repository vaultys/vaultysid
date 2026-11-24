// Package brainpool adapts the curve API used by gmrtd to elliptic2.
package brainpool

import (
	"crypto/elliptic"

	curves "github.com/RyuaNerin/elliptic2/brainpool"
)

func P160r1() elliptic.Curve { return curves.BrainpoolP160r1() }
func P192r1() elliptic.Curve { return curves.BrainpoolP192r1() }
func P224r1() elliptic.Curve { return curves.BrainpoolP224r1() }
func P256r1() elliptic.Curve { return curves.BrainpoolP256r1() }
func P320r1() elliptic.Curve { return curves.BrainpoolP320r1() }
func P384r1() elliptic.Curve { return curves.BrainpoolP384r1() }
func P512r1() elliptic.Curve { return curves.BrainpoolP512r1() }
