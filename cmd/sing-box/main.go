//go:build !generate && !windows

package main

import "github.com/sagernet/sing-box/log"

func main() {
	if err := mainCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
