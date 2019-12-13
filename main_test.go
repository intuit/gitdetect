package main

import (
	"encoding/json"
	"fmt"
	"github.com/intuit/gitdetect/defect"
	"github.com/intuit/gitdetect/secret/exploit"
	"github.com/intuit/gitdetect/test/secret-files"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"testing"
)

const (
	configFileName = "sample-gitdetect.conf.yaml"
)

var commonCliArgs []string

func setup() (err error) {
	exploit.SetAWSExploiter(MockAWSSTSExploiter{})
	outputDir, err := ioutil.TempDir("", "gidetect")
	if err != nil {
		return
	}

	configFilePath := path.Join(getProjectDir(), configFileName)
	commonCliArgs = []string{commandArg(CLI_ARG_CONFIG_FILENAME), configFilePath, commandArg(CLI_ARG_OUTPUT_DIR), outputDir}
	fmt.Printf("%v\n", commonCliArgs)
	return

}

func TestMain(m *testing.M) {

	err := setup()
	if err != nil {
		panic("Test setup failed: " + err.Error())
	}

	code := m.Run()
	os.Exit(code)
}

func TestLocalScan(t *testing.T) {

	localScanDir := getProjectDir()
	cliArgs := []string{commandArg(CLI_ARG_LOCAL_SCAN_DIR), localScanDir}
	cliArgs = append(commonCliArgs, cliArgs...)

	defectReport, err := doMain(cliArgs)
	if err != nil {
		t.Errorf("Scanning failed, error: %s", err.Error())
	}

	validateLocalRepoValues(t, defectReport, localScanDir)
	validateDefects(t, defectReport)

	return

}

func TestGithubScan(t *testing.T) {

	githubToken := os.Getenv("GITHUBTOKEN")
	if githubToken == "" {
		t.Log("Quitting, test environment not setup.")
		return
	}

	githubHostName := os.Getenv("GITHUBHOSTNAME")
	if githubHostName == "" {
		githubHostName = "github.com"
	}

	githubRepoNameBranch := os.Getenv("REPONAMEBRANCH")
	if githubRepoNameBranch == "" {
		githubRepoNameBranch = "intuit/gitdetect"
	}

	cliArgs := []string{commandArg(CLI_ARG_GIT_ACCESS_TOKEN), githubToken, commandArg(CLI_ARG_GIT_HOSTNAME), githubHostName, commandArg(CLI_ARG_GIT_REPO_NAME), githubRepoNameBranch}
	cliArgs = append(commonCliArgs, cliArgs...)

	defectReport, err := doMain(cliArgs)
	if err != nil {
		t.Errorf("Scanning failed, error: %s", err.Error())
	}

	validateGitRepoValues(t, defectReport)
	validateDefects(t, defectReport)
}

func getProjectDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return path.Dir(filename)
}

func TestParameterValidation(t *testing.T) {

	bogusToken := "12345678989f83e84f5d2123455a8549d6812345"

	//test no parameters
	_, err := doMain([]string{})
	if err == nil {
		t.Fatal("empty argument list should return error")
	}

	//test bad local scan dir
	badLocalDirArgs := append(commonCliArgs, []string{commandArg(CLI_ARG_LOCAL_SCAN_DIR), getProjectDir() + "bad-dir"}...)

	_, err = doMain(badLocalDirArgs)
	if err == nil {
		t.Fatal("non existing local scan dir sshould return error")
	}

	//test missing github token
	missingTokenArgs := append(commonCliArgs, []string{commandArg(CLI_ARG_GIT_REPO_NAME), "myorg/myproj/mybranch"}...)

	_, err = doMain(missingTokenArgs)
	if err == nil {
		t.Fatal("missing github token should return error")
	}

	//test bad repo name format
	badReopNameFormatArgs := append(commonCliArgs, []string{commandArg(CLI_ARG_GIT_REPO_NAME), "bad-reponame-format", commandArg(CLI_ARG_GIT_ACCESS_TOKEN), bogusToken}...)

	_, err = doMain(badReopNameFormatArgs)
	if err == nil {
		t.Fatal("missing github token should return error")
	}

	//test unauthorized github token
	unauthorizedGithubTokenArgs := append(commonCliArgs, []string{commandArg(CLI_ARG_GIT_REPO_NAME), "myorg/myproj/mybranch", commandArg(CLI_ARG_GIT_ACCESS_TOKEN), bogusToken,
		commandArg(CLI_ARG_GIT_LAST_MODIFIED_CUTOFF), "5"}...)

	_, err = doMain(unauthorizedGithubTokenArgs)
	if err == nil {
		t.Fatal("invalidf github token should return error")
	}

	//test invalid last scan cutoff
	invalidScanCutoffValueArgs := append(commonCliArgs, []string{commandArg(CLI_ARG_GIT_REPO_NAME), "myorg/myproj/mybranch", commandArg(CLI_ARG_GIT_ACCESS_TOKEN), bogusToken,
		commandArg(CLI_ARG_GIT_LAST_MODIFIED_CUTOFF), "-5"}...)

	_, err = doMain(invalidScanCutoffValueArgs)

	if err == nil {
		t.Fatal("invalid last scan cutoff should return error")
	}

}

//An awsExploiter mock implementation
type MockAWSSTSExploiter struct {
}

func (this MockAWSSTSExploiter) AccessAWS(keyID, keySecret string) (awsInfo *exploit.AWSInfo) {

	if keySecret == secret_files.MockActiveAWSSecretKey {
		if keyID == secret_files.MockActiveAWSSecretKeyID {
			awsInfo = &exploit.AWSInfo{Arn: "testarn", Account: "testaccount", UserID: "testuserid"}
			return
		}
	}

	return

}

func validateDefects(t *testing.T, defectReport *defect.Report) {

	report := defectReport.Repositories
	assertEqual(t, 8, defectReport.DefectCount, "DefectCount")
	numOfDefectFilesChecked := 0

	for _, fileDefects := range report {
		for file, defects := range fileDefects.Defects {

			switch file.Filename {
			case path.Join("test", "secret-files", "OneSecret.txt"):
				validateSingleSecretOccurence(t, defects)
				numOfDefectFilesChecked++
			case path.Join("test", "secret-files", "TwoDistinctSecrets.txt"):
				validateMultiDistinctSecretOccurence(t, defects)
				numOfDefectFilesChecked++
			case path.Join("test", "secret-files", "TwoDistinctSecretsCommonLine"):
				validateCommonLineDistinctSecretOccurence(t, defects)
				numOfDefectFilesChecked++
			case path.Join("test", "secret-files", "TwoIdenticalSecrets.txt"):
				validateMultiIdenticalSecretOccurence(t, defects)
				numOfDefectFilesChecked++
			case path.Join("test", "secret-files", "activeSecret.go"):
				validateActiveSecretOccurence(t, defects)
				numOfDefectFilesChecked++

			}

		}

	}
	assertEqual(t, 5, numOfDefectFilesChecked, "Not all test detection files were tested")
}

//validate reporting for file containing a single secret
func validateSingleSecretOccurence(t *testing.T, defectList []*defect.Defect) {

	t.Log("validateSingleSecretOccurence")
	assertEqual(t, 1, len(defectList), "Number of Defects")
	defect := defectList[0]
	assertEqual(t, 1, len(defect.Lines), "Number of line occurrences")
	assertEqual(t, 3, defect.Lines[0], "Defect line number")

}

//validate reporting for file containing two distinct secrets on two distinct lines
func validateMultiDistinctSecretOccurence(t *testing.T, defectList []*defect.Defect) {

	t.Log("validateMultiDistinctSecretOccurence")
	assertEqual(t, 2, len(defectList), "Number of Defects")

	defect1 := defectList[0]
	defect2 := defectList[1]
	assertNotEqual(t, defect1.Lines[0], defect2.Lines[0], "Distinct secret should be on distinct line number")

	for _, defect := range defectList {

		assertEqual(t, 1, len(defect.Lines), "Number of line occurrences")
		assertTrue(t, defect.Lines[0] == 4 || defect.Lines[0] == 5, "Defect line number")
	}
}

//validate reporting for file containing two distinct secrets on two distinct lines
func validateCommonLineDistinctSecretOccurence(t *testing.T, defectList []*defect.Defect) {

	t.Log("validateCommonLineDistinctSecretOccurence")
	assertEqual(t, 2, len(defectList), "Number of Defects")

	defect1 := defectList[0]
	defect2 := defectList[1]
	assertEqual(t, defect1.Lines[0], defect2.Lines[0], "Distinct secrets expected on common line number")

	for _, defect := range defectList {

		assertEqual(t, 1, len(defect.Lines), "Number of line occurrences")
	}
}

//validate reporting for file containing two identical secrets on two distinct lines
func validateMultiIdenticalSecretOccurence(t *testing.T, defectList []*defect.Defect) {

	t.Log("validateMultiIdenticalSecretOccurence")
	assertEqual(t, 1, len(defectList), "Number of Defects")

	defect := defectList[0]
	assertEqual(t, 2, len(defect.Lines), "Number of lines")
	assertNotEqual(t, defect.Lines[0], defect.Lines[1], "Identical secrets on distinct line numbers")
	assertNotEqual(t, defect.Lines[0], defect.Lines[1], "Distinct defect should be on distinct line number")
}

func validateActiveSecretOccurence(t *testing.T, defectList []*defect.Defect) {

	t.Log("validateActiveSecretOccurence")
	assertEqual(t, 1, len(defectList), "Number of Defects")
	defect := defectList[0]
	assertEqual(t, 1, len(defect.Lines), "Number of line occurrences")
	assertEqual(t, 7, defect.Lines[0], "Defect line number")

	awsInfo := exploit.AWSInfo{}

	json.Unmarshal([]byte(defect.AdditionalInfo), &awsInfo)
	assertEqual(t, "testaccount", awsInfo.Account, "active secret aws account")
	assertEqual(t, "testarn", awsInfo.Arn, "active secret aws arn")
	assertEqual(t, "testuserid", awsInfo.UserID, "active secret aws userid")
}

//validate reporting for Local filesystem repository attributes
func validateLocalRepoValues(t *testing.T, defectReport *defect.Report, localScanDir string) {
	t.Log("validateLocalRepoValues")

	report := defectReport.Repositories

	assertEqual(t, 1, len(report), "RepositoryCount")

	for repository := range report {

		assertEqual(t, repository.LocalDir, localScanDir, "scanDirectory")
	}
}

//validate reporting for Git repository attributes
func validateGitRepoValues(t *testing.T, defectReport *defect.Report) {
	t.Log("validateGitRepoValues")

	report := defectReport.Repositories

	assertEqual(t, 1, len(report), "RepositoryCount")

	for repository := range report {

		assertNotEmpty(t, repository.LastPush, "FileRepo LastPush")
		assertNotEmpty(t, repository.Org, "FileRepo Org")
		assertNotEmpty(t, repository.Name, "FileRepo Name")
		assertNotEmpty(t, repository.Branch, "FileRepo Branch")
		assertNotEqual(t, 0, repository.ID, "FileRepo ID")
		assertNotEmpty(t, repository.Head, "Head")
	}

}

func commandArg(arg string) string {
	return "-" + arg
}

//test help function
func assertNotEqual(t *testing.T, unexpected interface{}, actual interface{}, msg string) {
	if actual == unexpected {
		t.Fatalf("%s, uexpected value %v", msg, actual)
	}
}

//test help function
func assertEqual(t *testing.T, expected interface{}, actual interface{}, msg string) {
	if actual != expected {
		t.Fatalf("%s, expected: %v actual: %v", msg, expected, actual)
	}
}

//test help function
func assertTrue(t *testing.T, actual bool, msg string) {
	if actual != true {
		t.Fatalf("%s, expected: true actual: %t", msg, actual)
	}
}

//test help function
func assertNotEmpty(t *testing.T, actual string, msg string) {
	if actual == "" {
		t.Fatalf("%s, value is empty", msg)
	}
}
