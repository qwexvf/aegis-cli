// Package ghactions parses GitHub Actions workflow YAML into the
// minimal domain shape needed by the risk heuristics. The full Actions
// schema is intentionally not modeled — only the fields that drive a
// finding are extracted.
package ghactions

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// FindWorkflows returns every `.github/workflows/*.{yml,yaml}` path
// under root. Order is filesystem-walk order; callers may sort for
// stable output.
func FindWorkflows(root string) ([]string, error) {
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("ghactions: read workflows dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out, nil
}

// Parse reads one workflow file and returns a domain.Workflow with
// line-accurate locations for evidence reporting. Malformed YAML is
// returned as an error; the caller decides whether to skip or fail.
func Parse(path string) (domain.Workflow, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return domain.Workflow{}, fmt.Errorf("ghactions: read %s: %w", path, err)
	}
	return ParseBytes(path, body)
}

// ParseBytes parses workflow YAML from memory. Separate from Parse so
// tests can avoid disk fixtures.
func ParseBytes(path string, body []byte) (domain.Workflow, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(body, &root); err != nil {
		return domain.Workflow{}, fmt.Errorf("ghactions: parse %s: %w", path, err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return domain.Workflow{}, fmt.Errorf("ghactions: %s: empty document", path)
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return domain.Workflow{}, fmt.Errorf("ghactions: %s: top-level is not a mapping", path)
	}

	wf := domain.Workflow{Path: path}
	for i := 0; i < len(top.Content); i += 2 {
		key, val := top.Content[i], top.Content[i+1]
		switch key.Value {
		case "name":
			wf.Name = val.Value
		case "on":
			wf.On = extractEvents(val)
		case "permissions":
			wf.Permissions = parsePermissions(val)
		case "jobs":
			wf.Jobs = parseJobs(path, val)
		}
	}
	return wf, nil
}

// extractEvents flattens the `on:` field into the set of event names.
// `on:` accepts three shapes: scalar ("push"), sequence ([push, pull_request]),
// or mapping ({push: {branches: [main]}, pull_request_target: null}).
func extractEvents(n *yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		out := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				out = append(out, c.Value)
			}
		}
		return out
	case yaml.MappingNode:
		out := make([]string, 0, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
		return out
	}
	return nil
}

// parsePermissions handles the three shapes of `permissions:`:
//
//	permissions: read-all
//	permissions: write-all
//	permissions:
//	  contents: read
//	  pull-requests: write
func parsePermissions(n *yaml.Node) domain.WorkflowPermissions {
	p := domain.WorkflowPermissions{Line: n.Line}
	switch n.Kind {
	case yaml.ScalarNode:
		p.Mode = n.Value
	case yaml.MappingNode:
		p.Mode = "scopes"
		p.Scopes = map[string]string{}
		for i := 0; i < len(n.Content); i += 2 {
			p.Scopes[n.Content[i].Value] = n.Content[i+1].Value
		}
	}
	return p
}

func parseJobs(path string, n *yaml.Node) []domain.WorkflowJob {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]domain.WorkflowJob, 0, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		idNode, jobNode := n.Content[i], n.Content[i+1]
		if jobNode.Kind != yaml.MappingNode {
			continue
		}
		job := domain.WorkflowJob{ID: idNode.Value, Line: idNode.Line}
		for j := 0; j < len(jobNode.Content); j += 2 {
			k, v := jobNode.Content[j], jobNode.Content[j+1]
			switch k.Value {
			case "name":
				job.Name = v.Value
			case "runs-on":
				job.RunsOn = v.Value
			case "permissions":
				job.Permissions = parsePermissions(v)
			case "steps":
				job.Steps = parseSteps(path, v)
			}
		}
		out = append(out, job)
	}
	return out
}

func parseSteps(path string, n *yaml.Node) []domain.WorkflowStep {
	if n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]domain.WorkflowStep, 0, len(n.Content))
	for _, sn := range n.Content {
		if sn.Kind != yaml.MappingNode {
			continue
		}
		step := domain.WorkflowStep{Line: sn.Line}
		for i := 0; i < len(sn.Content); i += 2 {
			k, v := sn.Content[i], sn.Content[i+1]
			switch k.Value {
			case "name":
				step.Name = v.Value
			case "uses":
				ref := parseActionRef(v.Value)
				ref.File = path
				ref.Line = v.Line
				step.Uses = &ref
			case "run":
				step.Run = &domain.RunScript{
					Body: v.Value,
					File: path,
					Line: v.Line,
				}
			case "shell":
				if step.Run != nil {
					step.Run.Shell = v.Value
				}
			case "with":
				step.With = scalarMap(v)
			case "env":
				step.Env = scalarMap(v)
			}
		}
		if step.Uses == nil && step.Run == nil {
			continue
		}
		out = append(out, step)
	}
	return out
}

// parseActionRef splits `owner/repo[/path]@ref` (or local/docker forms)
// into the domain shape. Returns Kind=Remote with empty fields for
// unparseable inputs; the heuristic layer is responsible for filtering.
func parseActionRef(raw string) domain.ActionRef {
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, ".\\") {
		return domain.ActionRef{Kind: domain.ActionRefLocal, Path: raw}
	}
	if strings.HasPrefix(raw, "docker://") {
		return domain.ActionRef{Kind: domain.ActionRefDocker, Path: raw}
	}
	ref := domain.ActionRef{Kind: domain.ActionRefRemote}
	at := strings.Index(raw, "@")
	if at >= 0 {
		ref.Ref = raw[at+1:]
		raw = raw[:at]
	}
	parts := strings.SplitN(raw, "/", 3)
	if len(parts) >= 2 {
		ref.Owner = parts[0]
		ref.Repo = parts[1]
	}
	if len(parts) == 3 {
		ref.Path = parts[2]
	}
	return ref
}

// scalarMap collects a mapping node's scalar children into a flat
// map[string]string. Non-scalar values (sequences/nested maps) are
// rendered as their literal value for matching purposes.
func scalarMap(n *yaml.Node) map[string]string {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]string, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1].Value
	}
	return out
}
