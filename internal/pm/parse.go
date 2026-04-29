package pm

import "strings"

// ParseInstallArgsWith walks an install argv and returns the positional
// package specs. Flags are skipped; flags that consume a separate value
// token are recognized via the per-PM takesValue predicate. The argv
// passed in must NOT include the install subcommand itself.
//
// "--flag=value" is handled implicitly because the value is glued to
// the flag.
func ParseInstallArgsWith(argv []string, takesValue func(flag string) bool) []PackageSpec {
	specs := make([]PackageSpec, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			if takesValue != nil && takesValue(a) && i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				i++
			}
			continue
		}
		specs = append(specs, parseSpec(a))
	}
	return specs
}
