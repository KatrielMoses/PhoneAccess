package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"text/tabwriter"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/storage"
	"github.com/spf13/cobra"
)

func newCasesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "cases",
		Short:        "Manage saved investigation cases",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}

	cmd.AddCommand(&cobra.Command{
		Use:          "list",
		Short:        "List all saved investigations",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := storage.Open("")
			if err != nil {
				return err
			}
			defer s.Close()
			invs, err := s.ListInvestigations()
			if err != nil {
				return err
			}
			printInvestigationsTable(cmd, invs)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "show <id>",
		Short:        "Show a saved investigation report",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			s, err := storage.Open("")
			if err != nil {
				return err
			}
			defer s.Close()
			reportJSON, err := s.GetInvestigationReport(id)
			if err != nil {
				return err
			}
			var report core.InvestigationReport
			if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprint(out, NewTerminalRenderer().Render(&report))

			children, err := s.ListChildInvestigations(id)
			if err == nil && len(children) > 0 {
				tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "\nLINKED PIVOTS")
				fmt.Fprintln(tw, "ID\tArtifact\tType\tRisk Band\tDate")
				for _, c := range children {
					artifact := c.PhoneE164
					if c.PivotValue != "" {
						artifact = c.PivotValue
					}
					fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n",
						c.ID, artifact, c.PivotType, c.RiskBand, c.CreatedAt.Format("2006-01-02 15:04"))
				}
				tw.Flush()
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "tag <id> <tag>",
		Short:        "Add a tag to an investigation",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			s, err := storage.Open("")
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.UpdateTag(id, args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Added tag %q to case #%d\n", args[1], id)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "note <id> <text>",
		Short:        "Add a note to an investigation",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			s, err := storage.Open("")
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.UpdateNote(id, args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Added note to case #%d\n", id)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "name <id> <name>",
		Short:        "Set a case name for an investigation",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			s, err := storage.Open("")
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.UpdateName(id, args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Set name %q for case #%d\n", args[1], id)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "delete <id>",
		Short:        "Delete an investigation and its pivots",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			s, err := storage.Open("")
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.Delete(id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted case #%d\n", id)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "search <query>",
		Short:        "Search across case names, tags, notes, and phone numbers",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := storage.Open("")
			if err != nil {
				return err
			}
			defer s.Close()
			invs, err := s.Search(args[0])
			if err != nil {
				return err
			}
			printInvestigationsTable(cmd, invs)
			return nil
		},
	})

	return cmd
}

func printInvestigationsTable(cmd *cobra.Command, invs []storage.Investigation) {
	if len(invs) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No investigations found.")
		return
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPhone\tCase Name\tRisk Band\tDate\tTag Count")
	for _, inv := range invs {
		dateStr := inv.CreatedAt.Format("2006-01-02 15:04")
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\n",
			inv.ID, inv.PhoneE164, inv.CaseName, inv.RiskBand, dateStr, len(inv.Tags))
	}
	tw.Flush()
}
