package rule

//package rule implements the test conditions for secret detection involving regular expressions matching and entropy calculation.

import (
	"math"
	"regexp"
)

const (
	//TARGET_GROUP_NAME regex configuration group name for entropy calculation
	TARGET_GROUP_NAME = "suspect"
)

//Rule represent the conditions that must be met to realize secret detection
type Rule struct {
	Target    []*regexp.Regexp
	Except    []*regexp.Regexp
	Entropy   float32
	Tag       string
	ExploitFn string
}

//List collection of Rule
type List struct {
	Rules []Rule
}

//Match takes input data and returns one or more string matches when all conditions in Rule are met.
func (rule *Rule) Match(text string) (matches []string, found bool) {

	if regexMatches, foundRegExMatch := rule.matchTargetRule(text); foundRegExMatch {
		for _, regExMatch := range regexMatches {
			if rule.Entropy == 0 || float32(Entropy(regExMatch)) >= rule.Entropy {
				if !rule.matchExclusionRule(text) {
					matches = append(matches, regExMatch)
					//all rule conditions met
					found = true
				}
			}
		}
	}

	return
}

func (rule *Rule) matchTargetRule(text string) (matches []string, found bool) {
	return matchOneOf(text, rule.Target)
}

func (rule *Rule) matchExclusionRule(text string) (found bool) {

	_, found = matchOneOf(text, rule.Except)
	return
}

func matchOneOf(text string, rules []*regexp.Regexp) (matches []string, found bool) {

	for _, rule := range rules {
		if rule.MatchString(text) {
			found = true
			matchedGroups := rule.FindAllStringSubmatch(text, -1)

			for i := 0; i < len(matchedGroups); i++ {
				for j, name := range rule.SubexpNames() {
					if name == TARGET_GROUP_NAME {
						matches = append(matches, matchedGroups[i][j])
					}
				}
			}
			//if no subgroup was indicated, return the whole matched expression
			if found && len(matches) == 0 {
				matches = rule.FindAllString(text, -1)
			}

		}
	}

	return
}

//Entropy returns the Shanon entropy of the input string
func Entropy(s string) float64 {
	m := map[rune]float64{}
	for _, r := range s {
		m[r]++
	}
	var hm float64
	for _, c := range m {
		hm += c * math.Log2(c)
	}
	l := float64(len(s))

	return math.Log2(l) - hm/l
}
