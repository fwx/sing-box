package main

import (
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run service",
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	mainCommand.AddCommand(commandRun)
}

// run() is implemented in platform-specific files:
// - cmd_run_windows.go for Windows (Named Pipe IPC)
// - cmd_run_other.go for other platforms (file-based config)
