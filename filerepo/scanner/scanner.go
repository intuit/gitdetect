package scanner

//package scanner is used for reading files and testing the file input stream with the configured detection rules.

import (
	"bufio"
	"fmt"
	"github.com/intuit/gitdetect/rule"
	"github.com/intuit/gitdetect/secret"
	"log"
	"os"
	"path/filepath"
)

// DebugPrintSecrets when set to true lines detected with secrets are printed to stdout
var DebugPrintSecrets bool

//FileScanner contains the local file directory to be scanned and the secret detection Rules with which to test the file input stream.
type FileScanner struct {
	Rules   []rule.Rule
	RootDir string
}

//Scan reads all files contained in this RootDir and tests the file input stream for Rules matches.  repoSecrets contains the a list of secrets detected in this RootDir
func (this *FileScanner) Scan() (repoSecrets []secret.Secret) {

	dir := this.RootDir

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Uresolvable path %q: %v\n", dir, err)
			return err
		}
		if info.IsDir() {
			return nil
		}

		fileSecrets := this.scanFile(path)
		repoSecrets = append(repoSecrets, fileSecrets...)

		return nil
	})

	return
}

func (this *FileScanner) scanFile(filename string) (secrets []secret.Secret) {

	fh, err := os.Open(filename)

	if err != nil {
		log.Printf("Error opening file %s, %s", filename, err.Error())
		return // there was a problem opening the file.
	}
	fileScanner := bufio.NewScanner(fh)
	defer fh.Close()

	lineCounter := 0
	for fileScanner.Scan() {

		line := fileScanner.Text()
		lineCounter++

		for _, rule := range this.Rules {
			if matches, found := rule.Match(line); found {
				if DebugPrintSecrets {
					fmt.Printf("%s, line, %d: %s\n", filename, lineCounter, line)
				}
				for _, match := range matches {
					secrets = append(secrets, secret.NewSecret(filename, match, lineCounter, rule))
				}
			}
		}
	}
	return
}
