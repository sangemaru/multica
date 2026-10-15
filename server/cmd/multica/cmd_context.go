package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/multica-ai/multica/server/internal/cli"
	"github.com/multica-ai/multica/server/pkg/protocol"
	"github.com/spf13/cobra"
)

var contextCmd = &cobra.Command{Use: "context", Short: "Read task-bound operational context"}

func newContextRefreshCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "refresh", Short: "Recheck explicitly selected sources for the running task", Args: cobra.NoArgs, RunE: runContextRefresh}
	cmd.Flags().String("project-id", "", "Required expected project UUID")
	cmd.Flags().String("issue-id", "", "Required initial task-bound issue UUID")
	cmd.Flags().String("output", "json", "Output format: json")
	return cmd
}

func init() {
	contextCmd.AddCommand(newContextRefreshCmd())
}

func runContextRefresh(cmd *cobra.Command, _ []string) error {
	projectID, _ := cmd.Flags().GetString("project-id")
	issueID, _ := cmd.Flags().GetString("issue-id")
	output, _ := cmd.Flags().GetString("output")
	if output != "json" || !protocol.CanonicalContextID(projectID) || !protocol.CanonicalContextID(issueID) {
		return fmt.Errorf("context refresh requires --project-id and --issue-id <canonical UUID>, and --output json")
	}
	if !inDaemonManagedExecutionContext() || !strings.HasPrefix(strings.TrimSpace(os.Getenv("MULTICA_TOKEN")), cli.TaskTokenPrefix) {
		return fmt.Errorf("context refresh requires a daemon task and task-scoped MULTICA_TOKEN")
	}
	expected := protocol.ContextBinding{TaskID: os.Getenv("MULTICA_TASK_ID"), WorkspaceID: os.Getenv("MULTICA_WORKSPACE_ID"),
		ProjectID: projectID, IssueID: issueID}
	for _, id := range []string{expected.TaskID, expected.WorkspaceID, os.Getenv("MULTICA_AGENT_ID")} {
		if !protocol.CanonicalContextID(id) {
			return fmt.Errorf("context refresh requires daemon-provided task, agent and workspace UUIDs; no owner fallback")
		}
	}
	client, err := newAPIClient(cmd)
	if err != nil {
		return err
	}
	ctx, cancel := cli.APIContext(cmd.Context())
	defer cancel()
	response, err := client.RefreshTaskContext(ctx, expected)
	if err != nil {
		return err
	}
	return cli.PrintJSON(cmd.OutOrStdout(), response)
}
