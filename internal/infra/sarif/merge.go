package sarif

import (
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// MergedToSARIF combines package scan findings (CIResult) and workflow
// scan findings (ActionsScanResult) into a single SARIF 2.1.0 Log with
// two runs[] — one per scanner. This is the standard SARIF approach for
// multi-tool output: each run has its own tool driver and rule set.
func MergedToSARIF(ciResult usecase.CIResult, actionsResult usecase.ActionsScanResult, toolVersion, baseDir string) Log {
	ciLog := CIToSARIF(ciResult, toolVersion)
	actionsLog := ActionsToSARIF(actionsResult, toolVersion, baseDir)

	// Rename drivers to distinguish the two scanners in UI.
	ciLog.Runs[0].Tool.Driver.Name = "aegis-cli/packages"
	actionsLog.Runs[0].Tool.Driver.Name = "aegis-cli/actions"

	return Log{
		Version: Version210,
		Schema:  schema210,
		Runs:    append(ciLog.Runs, actionsLog.Runs...),
	}
}
