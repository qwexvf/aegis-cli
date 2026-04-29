package domain

// BuiltinAllowRules returns the curated default allowlist that ships
// with the binary. Entries are well-known packages whose flagged
// capabilities are part of their legitimate behavior. Without these
// defaults, the risk engine produces unacceptable false positives on
// the majority of real npm projects.
//
// Adding a rule here is an explicit assertion: "we, the Aegis
// maintainers, have verified this package legitimately needs this
// capability." Curate carefully — every entry weakens the gate.
//
// Convention: keep VersionRange="*" (any version) unless we have a
// specific reason to narrow it. If a future version introduces
// genuinely new dangerous behavior, the user can override the rule
// in their project allowlist.
func BuiltinAllowRules() []AllowRule {
	const src = "builtin"
	return []AllowRule{
		// Template compilers — every one of these uses Function()
		// constructor for runtime template compilation, which is
		// what dynamic-eval detection picks up.
		{Ecosystem: EcoNpm, Name: "lodash", Capability: CapDynamicEval,
			Reason: "lodash._.template compiles templates via Function()", Source: src},
		{Ecosystem: EcoNpm, Name: "underscore", Capability: CapDynamicEval,
			Reason: "underscore.template uses Function() for template compilation", Source: src},
		{Ecosystem: EcoNpm, Name: "handlebars", Capability: CapDynamicEval,
			Reason: "handlebars compiles templates via Function()", Source: src},
		{Ecosystem: EcoNpm, Name: "ejs", Capability: CapDynamicEval,
			Reason: "ejs uses Function() for template compilation", Source: src},

		// Build tools — legitimately spawn worker processes / their
		// own native binaries during build.
		{Ecosystem: EcoNpm, Name: "webpack", Capability: CapShellSpawn,
			Reason: "webpack spawns worker processes and loaders", Source: src},
		{Ecosystem: EcoNpm, Name: "@babel/core", Capability: CapShellSpawn,
			Reason: "babel spawns worker processes for parallel transforms", Source: src},
		{Ecosystem: EcoNpm, Name: "esbuild", Capability: CapShellSpawn,
			Reason: "esbuild spawns its native Go binary as a child process", Source: src},
		{Ecosystem: EcoNpm, Name: "rollup", Capability: CapShellSpawn,
			Reason: "rollup uses workers for parallel bundling", Source: src},
		{Ecosystem: EcoNpm, Name: "vite", Capability: CapShellSpawn,
			Reason: "vite spawns dev-server child processes", Source: src},
		{Ecosystem: EcoNpm, Name: "parcel", Capability: CapShellSpawn,
			Reason: "parcel uses worker processes", Source: src},
		{Ecosystem: EcoNpm, Name: "nodemon", Capability: CapShellSpawn,
			Reason: "nodemon spawns the user's node process", Source: src},

		// HTTP clients — net-egress is literally the package's purpose.
		{Ecosystem: EcoNpm, Name: "node-fetch", Capability: CapNetEgress,
			Reason: "package's stated purpose is HTTP fetch", Source: src},
		{Ecosystem: EcoNpm, Name: "axios", Capability: CapNetEgress,
			Reason: "package's stated purpose is HTTP", Source: src},
		{Ecosystem: EcoNpm, Name: "got", Capability: CapNetEgress,
			Reason: "package's stated purpose is HTTP", Source: src},
		{Ecosystem: EcoNpm, Name: "undici", Capability: CapNetEgress,
			Reason: "package's stated purpose is HTTP (Node's reference HTTP client)", Source: src},

		// Native-build packages — declare an install hook to compile
		// or download platform-specific binaries.
		{Ecosystem: EcoNpm, Name: "fsevents", Capability: CapInstallHookExec,
			Reason: "macOS native fs watcher compiled at install time", Source: src},
		{Ecosystem: EcoNpm, Name: "node-sass", Capability: CapInstallHookExec,
			Reason: "compiles libsass binary at install time", Source: src},
		{Ecosystem: EcoNpm, Name: "sharp", Capability: CapInstallHookExec,
			Reason: "downloads libvips binary at install time", Source: src},
		{Ecosystem: EcoNpm, Name: "better-sqlite3", Capability: CapInstallHookExec,
			Reason: "compiles native sqlite3 at install time", Source: src},
		{Ecosystem: EcoNpm, Name: "bcrypt", Capability: CapInstallHookExec,
			Reason: "compiles native bcrypt at install time", Source: src},
	}
}
