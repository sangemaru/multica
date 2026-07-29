package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/multica-ai/multica/server/internal/cli"
)

type authorizationDecisionExplanation struct {
	ID                 string   `json:"id"`
	TaskID             string   `json:"task_id,omitempty"`
	Path               string   `json:"path"`
	EvaluationPhase    string   `json:"evaluation_phase"`
	Action             string   `json:"action"`
	PrincipalType      string   `json:"principal_type"`
	PrincipalID        string   `json:"principal_id,omitempty"`
	CredentialClass    string   `json:"credential_class"`
	Outcome            string   `json:"outcome"`
	Enforcement        string   `json:"enforcement"`
	ReasonCode         string   `json:"reason_code"`
	PolicyVersion      string   `json:"policy_version"`
	PolicyLayer        string   `json:"policy_layer"`
	Explanation        string   `json:"explanation"`
	NextStep           string   `json:"next_step"`
	TaskCreated        bool     `json:"task_created"`
	ProviderCallStatus string   `json:"provider_call_status"`
	AllowedActions     []string `json:"allowed_actions,omitempty"`
	ExplicitDenies     []string `json:"explicit_denies,omitempty"`
	CreatedAt          string   `json:"created_at"`
}

var authorizationCmd = &cobra.Command{
	Use:   "authorization",
	Short: "Inspect authorization decisions",
}

var authorizationDecisionsCmd = &cobra.Command{
	Use:   "decisions",
	Short: "List recent authorization decisions",
	RunE:  runAuthorizationDecisions,
}

var authorizationExplainCmd = &cobra.Command{
	Use:   "explain <decision-id>",
	Short: "Explain why one authorization decision allowed or denied work",
	Args:  cobra.ExactArgs(1),
	RunE:  runAuthorizationExplain,
}

func init() {
	authorizationCmd.AddCommand(authorizationDecisionsCmd)
	authorizationCmd.AddCommand(authorizationExplainCmd)
	authorizationDecisionsCmd.Flags().Int("limit", 20, "Number of decisions to return (1-100)")
	authorizationDecisionsCmd.Flags().Int("offset", 0, "Number of recent decisions to skip")
	authorizationDecisionsCmd.Flags().String("output", "table", "Output format: table or json")
	authorizationExplainCmd.Flags().String("output", "text", "Output format: text or json")
}

func authorizationWorkspacePath(client *cli.APIClient) (string, error) {
	workspaceID := strings.TrimSpace(client.WorkspaceID)
	if workspaceID == "" {
		return "", fmt.Errorf("workspace ID is required: use --workspace-id, MULTICA_WORKSPACE_ID, or configure a workspace")
	}
	return "/api/workspaces/" + url.PathEscape(workspaceID) + "/authorization", nil
}

func runAuthorizationDecisions(cmd *cobra.Command, _ []string) error {
	client, err := newAPIClient(cmd)
	if err != nil {
		return err
	}
	path, err := authorizationWorkspacePath(client)
	if err != nil {
		return err
	}
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")
	if limit < 1 || limit > 100 || offset < 0 {
		return fmt.Errorf("--limit must be 1-100 and --offset must be non-negative")
	}
	ctx, cancel := cli.APIContext(context.Background())
	defer cancel()
	var decisions []authorizationDecisionExplanation
	if err := client.GetJSON(ctx,
		path+"/decisions?limit="+strconv.Itoa(limit)+"&offset="+strconv.Itoa(offset),
		&decisions,
	); err != nil {
		return fmt.Errorf("list authorization decisions: %w", err)
	}
	output, _ := cmd.Flags().GetString("output")
	if output == "json" {
		return cli.PrintJSON(cmd.OutOrStdout(), decisions)
	}
	if output != "table" {
		return fmt.Errorf("--output must be table or json")
	}
	rows := make([][]string, 0, len(decisions))
	for _, decision := range decisions {
		rows = append(rows, []string{
			decision.ID,
			decision.Outcome,
			decision.Action,
			decision.PolicyLayer,
			decision.ReasonCode,
			decision.EvaluationPhase,
			decision.CreatedAt,
		})
	}
	cli.PrintTable(cmd.OutOrStdout(),
		[]string{"ID", "OUTCOME", "ACTION", "POLICY_LAYER", "REASON", "PHASE", "CREATED_AT"},
		rows,
	)
	return nil
}

func runAuthorizationExplain(cmd *cobra.Command, args []string) error {
	client, err := newAPIClient(cmd)
	if err != nil {
		return err
	}
	path, err := authorizationWorkspacePath(client)
	if err != nil {
		return err
	}
	ctx, cancel := cli.APIContext(context.Background())
	defer cancel()
	var decision authorizationDecisionExplanation
	if err := client.GetJSON(ctx,
		path+"/decisions/"+url.PathEscape(strings.TrimSpace(args[0])),
		&decision,
	); err != nil {
		return fmt.Errorf("explain authorization decision: %w", err)
	}
	output, _ := cmd.Flags().GetString("output")
	if output == "json" {
		return cli.PrintJSON(cmd.OutOrStdout(), decision)
	}
	if output != "text" {
		return fmt.Errorf("--output must be text or json")
	}
	return writeAuthorizationDecisionExplanation(cmd.OutOrStdout(), decision)
}

func writeAuthorizationDecisionExplanation(w io.Writer, decision authorizationDecisionExplanation) error {
	_, err := fmt.Fprintf(w,
		"Decision: %s\nOutcome: %s (%s)\nAction: %s via %s (%s)\nPrincipal: %s / %s\nPolicy: %s (%s)\nReason: %s\nWhy: %s\nTask created: %t\nProvider call: %s\nNext step: %s\n",
		decision.ID,
		decision.Outcome,
		decision.Enforcement,
		decision.Action,
		decision.Path,
		decision.EvaluationPhase,
		decision.PrincipalType,
		decision.CredentialClass,
		decision.PolicyVersion,
		decision.PolicyLayer,
		decision.ReasonCode,
		decision.Explanation,
		decision.TaskCreated,
		decision.ProviderCallStatus,
		decision.NextStep,
	)
	return err
}
