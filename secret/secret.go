package secret

//package secret contains the Secret structure representing a unique secret value in a File.

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/intuit/gitdetect/rule"
	"github.com/intuit/gitdetect/secret/exploit"
	"log"
)

//Secret docuements detected secret metadata
type Secret struct {
	FileName   string
	Value      string
	LineNumber int
	Rule       rule.Rule
	ID         string
}

//NewSecret initialize and return Secret type
func NewSecret(fileName, secretValue string, lineNumber int, rule rule.Rule) (secret Secret) {

	secret.FileName = fileName
	secret.Value = secretValue
	secret.LineNumber = lineNumber
	secret.Rule = rule
	secret.setID()
	return
}

func (this *Secret) setID() {
	hash := md5.New()
	hash.Write([]byte(this.FileName + this.Value))
	this.ID = hex.EncodeToString(hash.Sum(nil))
}

//Exploit runs optionally set hook function ExploitFn
func (this *Secret) Exploit() (exploitInfo string) {

	if this.Rule.ExploitFn != "" {
		exploit := exploit.Exploit{Fn: this.Rule.ExploitFn, Secret: this.Value, Filename: this.FileName}
		if err := exploit.Run(); err == nil {
			exploitInfo = exploit.Output
		} else {
			log.Printf("ExploitFn failed with %s", err.Error())
		}
	}

	return
}
