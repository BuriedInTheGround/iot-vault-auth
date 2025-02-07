package main

import (
	"flag"
	"os"

	"github.com/BuriedInTheGround/iot-vault-auth/internal/tui"
	"github.com/BuriedInTheGround/iot-vault-auth/internal/vault"
)

func main() {
	tui.ProgramName = "vaultgen"
	flag.Parse()

	if len(flag.Args()) != 1 {
		tui.Errorf("missing vault file path")
	}

	vault, err := vault.GenerateVault()
	if err != nil {
		tui.Errorf("failed to generate vault: %v", err)
	}

	var f *os.File
	if name := flag.Arg(0); name == "-" {
		f = os.Stdout
	} else {
		f, err = os.Create(name)
		if err != nil {
			tui.Errorf("failed to create vault file: %v", err)
		}
		defer f.Close()
	}

	_, err = vault.WriteTo(f)
	if err != nil {
		tui.Errorf("failed to write vault file: %v", err)
	}
}
