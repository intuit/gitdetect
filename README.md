<p>
    <img src="./logo.svg" width="150" alt="Logo"/>
</p>

[![Build Status](https://travis-ci.org/intuit/gitdetect.svg?branch=master)](https://travis-ci.org/intuit/gitdetect)
[![codecov](https://codecov.io/gh/intuit/gitdetect/branch/master/graph/badge.svg)](https://codecov.io/gh/intuit/gitdetect)
[![Go Report Card](https://goreportcard.com/badge/github.com/intuit/gitdetect)](https://goreportcard.com/report/github.com/intuit/gitdetect)


**gitdetect**

A Github scanning tool to help you find misplaced secrets in your source code repository files.  *gitdetect* uses compound rules that combine regular expressions with an entropy threshold allowing a greatly reduced rate
of false positive detections relative to other tools.  *gitdetect* can also scan an arbitrary directory on the local filesystem. 

**Sample Configuration File**

The following yaml configuration file may be used to find AWS secret keys
```
secret-detection-rules:
- target:
  - \"(?P<suspect>[A-Za-z0-9\/+]{40})\"
  - '''(?P<suspect>[A-Za-z0-9\/+]{40})'''
  except:
  - \"EXAMPLE([A-Za-z0-9\/+]{33})\"
  - '''EXAMPLE([A-Za-z0-9\/+]{33})'''
  entropy: 4.5
  tag: AWS_SEC
  exploitfn: AwsSTS

- target:
  - \"(?P<suspect>sec[A-Za-z0-9\/+]{37})\"
  - '''(?P<suspect>sec[A-Za-z0-9\/+]{37})'''
  entropy: 4.5
  tag: MY_OTHER_SEC_TYPE


```
Description

`target:`       List of regular expressions where a match with any one of the expressions is required to continue evaluation.     
`except:`       Exclusion list of regular expressions where a match with any one of the expressions disqualifies a target match.  If no match is made, evaluation of the compound rule continues.     
`entropy:`      Minimum threshold value as measured by the Shanon Entropy of the matched string.    
`tag:`          Descriptive text to afix to a reported match.      
`exploitfn:`    The name of the method to call when a secret is detected.  This method must be defined in the secret/exploit package with the `*Exploit`.  Any data set in `Exploit.Output` will be shown as .  Gitdetect contains one such method called AwsSTS which is used to determine if a suspected AWS secret key is active.      

For example, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYKEYEXAMPLE" will be detected by the above rule because it matches the first regular expression listed under *target*, it does not match any of the regular expressions
listed under *except* and it has a shanon entropy value greater or equal to 4.5.

Note each `target` expressions has a named capturing group *suspect* `(?P<suspect>)`, an optional keyword recoginized by gitdetect.  When used, gitdetect applies the entropy threshold to the named group only.  In the above example
if the *suspect* group name was not used the entropy threshold would be applied to the entire matched string which includes the surrounding quotes.

**Usage of gitdetect:**
```
  -access-token string
    	github access token.
  -github-hostname string
    	github url hostname (default "github.com")
  -last-modified-cutoff int
    	The repository will not be scanned unless it was modified in the last number of days specified here. 0 indicates scan always.
  -local-scan-dir string
    	The local directory path to scan.  When set, github related options are ignored.
  -output-dir string
    	working dir and report genaration dir.
  -repo-name string
    	Fully qualified repo name in the format <owner>/<name>/[<branch>] e.g. my-org/my-proj for the default branch or my-org/my-proj/my-feature-branch. Leave blank for a full github scan.
  -rule-config string
    	Full path name of the detection rule configuration file.
```

**Example Usage**

Scan the gitdetect repository under the ABC org:

> ./gitdetect -access-token 73f5921499a9191817640d5e94486b50c0916c67 -rule-config  gitdetect.conf.yaml -output ./myoutput -repo-name ABC/gitdetect

Scan all public repositories on the XYZ enterprise Github:
> ./gitdetect -github-hostname xyz.github.com -access-token 73f5921499a9191817640d5e94486b50c0916c67 -rule-config gitdetect.conf.yaml -output ./myoutput  

Scan the local directory /home/jsmith/myapp
> ./gitdetect -rule-config gitdetect.conf.yaml -output /home/jsmith -local-scan-dir /home/jsmith/myapp


**Defect Report**

When gitdetect finishes running it will create a report file in the output directory named defectReport.yaml. Following is a sample report created by gitdetect

```
repositories:
  ? id: 101287
    org: myorg
    name: gitdetect
    branch: master
    head: 1234556412345123451234512345123458912345
    last-push: "2019-10-17"
  : defects:
      ? filename: test/filerepo/TwoDistinctSecrets.txt
      : - lines:
          - 4
          tag: AWS_SEC
        - lines:
          - 5
          tag: AWS_SEC
      ? filename: test/filerepo/TwoIdenticalSecrets.txt
      : - lines:
          - 4
          - 5
          tag: AWS_SEC
      ? filename: test/filerepo/activeSecret.go
      : - lines:
          - 4
          tag: AWS_SEC
          additional-info: '{"Account":"testaccount","Arn":"testarn","UserId":"testuserid"}'
      ? filename: README.md
      : - lines:
          - 45
          tag: AWS_SEC
      ? filename: test/filerepo/OneSecret.txt
      : - lines:
          - 3
          tag: AWS_SEC
defectcount: 7

```    

Noteworthy fields:

`additional-info:`  When a secret is confirmed to be active as determined by the optional `exploitfn`, `func (exploit *Exploit) AwsSTS() bool` may set Exploit.Output with any relevant JSON formatted data.  The data will be shown in this field.  
   
**Regular Expressions Syntax**  

*gitdetect* supports the golang RE2 subset of the PCRE syntax.  This means that backtracing is not supported.  For this reason the above example uses two separate expression, a single quote and a double quote version where a single expression would have been possible with PCRE backtracing.  The upside is improved performance.

**Contributions**
   
gitdetect welcomes contributions from everyone.  Please refer to the documentation under .github/CONTRIBUTING before submitting your pull request.