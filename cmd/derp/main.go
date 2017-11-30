package main

import (
	"context"
	"flag"
	"fmt"
	_ "github.com/adrpino/derpcipher"
	"io"
	"os"
	"strings"
)

type command interface {
	Name() string      // "foobar"
	Args() string      // "<baz> [quux...]"
	ShortHelp() string // "Foo the first bar"
	LongHelp() string  // "Foo the first bar meeting the following conditions..."
	//	Register(*flag.FlagSet) // command-specific flags
	Hidden() bool // indicates whether the command should be hidden from help output
	Run(*context.Context, []string) error
}

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to get working directory", err)
		os.Exit(1)
	}
	c := &Config{
		Args:       os.Args,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		WorkingDir: wd,
		Env:        os.Environ(),
	}
	os.Exit(c.Run())
}

// A Config specifies a full configuration for a dep execution.
type Config struct {
	WorkingDir     string    // Where to execute
	Args           []string  // Command-line arguments, starting with the program name.
	Env            []string  // Environment variables
	Stdout, Stderr io.Writer // Log output
}

func (c *Config) Run() int {
	// Build the list of available commands.
	commands := [...]command{
		&encryptCommand{},
		//&decryptCommand{},
		//&versionCommand{},
	}
	usage := func(w io.Writer) {
		fmt.Fprintln(w, "Derp tries to do your life easy")
	}

	cmdName, printCmdUsage, exit := parseArgs(c.Args)
	if exit {
		fmt.Println("i'm exiting")
		usage(c.Stderr)
		return 1
	}
	if printCmdUsage {
		fmt.Println("Hi! i'm printing a command help")
	}
	// iterate over commands
	for _, cmd := range commands {
		if cmd.Name() == cmdName {
			// Build flag set with global flags in there.
			fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
			fs.SetOutput(c.Stderr)
			//verbose := fs.Bool("v", false, "enable verbose logging")

			// Register the subcommand flags in there, too.
			//			cmd.Register(fs)
			fmt.Println("i'm using command %v", cmdName)

		}
	}

	return 0
}

func parseArgs(args []string) (cmdName string, printCmdUsage bool, exit bool) {
	fmt.Println("received", len(args), "arguments", args)
	isHelpArg := func() bool {
		return strings.Contains(strings.ToLower(args[1]), "help") || strings.ToLower(args[1]) == "-h"
	}

	switch len(args) {
	case 0, 1:
		exit = true
	case 2:
		if isHelpArg() {
			exit = true
		} else {
			cmdName = args[1]
		}
	default:
		if isHelpArg() {
			cmdName = args[2]
			printCmdUsage = true
		} else {
			cmdName = args[1]
		}
	}
	return cmdName, printCmdUsage, exit
}

type encryptCommand struct {
}

func (cmd *encryptCommand) Name() string { return "cipher" }
func (cmd *encryptCommand) Args() string { return "[root]" }

const encryptShortHelp = `Encrypts from files or stdin.`
const encryptLongHelp = `Someday I'll write this.`

func (cmd *encryptCommand) Hidden() bool      { return false }
func (cmd *encryptCommand) ShortHelp() string { return encryptShortHelp }
func (cmd *encryptCommand) LongHelp() string  { return encryptLongHelp }

//func (cmd *encryptCommand) Register(fs *flag.FlagSet) {
//	fs.BoolVar(&cmd.noExamples, "no-examples", false, "don't include example in Gopkg.toml")
//	fs.BoolVar(&cmd.skipTools, "skip-tools", false, "skip importing configuration from other dependency managers")
//	fs.BoolVar(&cmd.gopath, "gopath", false, "search in GOPATH for dependencies")
//}

func (cmd *encryptCommand) Run(ctx *context.Context, args []string) error {
	fmt.Println("hi there!")
	return nil

}
