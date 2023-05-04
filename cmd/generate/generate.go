package generate

import "github.com/spf13/cobra"

var (
	Cmd = &cobra.Command{
		Use:              "generate",
		Short:            "Generate a self-signed certificate",
		Long:             ``,
		TraverseChildren: true,
	}
)

func init() {
	Cmd.AddCommand(generateFromCsrCommand)
	Cmd.AddCommand(generateFromStdioCommand)
}
