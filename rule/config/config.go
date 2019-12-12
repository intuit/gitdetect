package config

//package config is used to interface with the detection rules configuration file.

import (
	"github.com/intuit/gitdetect/rule"
	"github.com/intuit/gitdetect/secret/exploit"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"regexp"
)

//RuleConfiguration configuration file Rule settings
type RuleConfiguration struct {
	Target    []string //regex
	Except    []string //regex
	Entropy   float32
	Tag       string
	ExploitFn string
}

//RuleConfigurationList List of RuleConfiguration
type RuleConfigurationList struct {
	SecretDetectionRules []RuleConfiguration `yaml:"secret-detection-rules,omitempty"`
}

//LoadDetectionRules read and load configuration file
func LoadDetectionRules(configFile string) rule.List {

	ruleConfigurationList := RuleConfigurationList{}

	yamlConf, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal("Failure reading rule configuration file.", err)
	}
	err = yaml.Unmarshal(yamlConf, &ruleConfigurationList)
	if err != nil {
		log.Fatal("Failure unmarshaling configuration file ruleConfigurationList.", err)
	}

	return ruleConfigurationList.Compile()
}

//Compile all the rules in the configuration
func (this *RuleConfigurationList) Compile() rule.List {

	var compiledRules []rule.Rule
	for _, rule := range this.SecretDetectionRules {
		compiledRules = append(compiledRules, rule.Compile())
	}
	return rule.List{Rules: compiledRules}
}

//Compile a single configuration rule
func (this *RuleConfiguration) Compile() rule.Rule {

	//verify that a configured exploit function is referencable
	exploitFnName := this.ExploitFn
	if exploitFnName != "" {
		if err := exploit.TryGetExploitFunction(exploitFnName); err != nil {
			panic("exploitFn " + exploitFnName + "as configured, was not found. " + err.Error())
		}
	}

	compiledRule := rule.Rule{
		Entropy:   this.Entropy,
		Tag:       this.Tag,
		Target:    regExListToCompiledRegExList(this.Target),
		Except:    regExListToCompiledRegExList(this.Except),
		ExploitFn: exploitFnName,
	}
	return compiledRule
}

func regExListToCompiledRegExList(regExRules []string) []*regexp.Regexp {

	var compiledRegExs []*regexp.Regexp
	for _, regEx := range regExRules {
		compiledRegEx, err := regexp.Compile(regEx)
		if err != nil {
			log.Fatal("Illegal golang regexp " + err.Error())
		}
		compiledRegExs = append(compiledRegExs, compiledRegEx)

	}
	return compiledRegExs
}
