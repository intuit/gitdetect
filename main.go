package main

// Package main provides the gitdetect cli tool entry point.  gitdetect is a Github scanning tool used to find secrets in your source code repository files.
// Compound rules combining regular expressions with an entropy threshold reduces the rate of false positive detections
// relative to other tools. gitdetect can also scan an arbitrary directory on the local filesystem.

import (
	"errors"
	"flag"
	"github.com/intuit/gitdetect/defect"
	"github.com/intuit/gitdetect/filerepo"
	"github.com/intuit/gitdetect/filerepo/github"
	"github.com/intuit/gitdetect/filerepo/localfs"
	"github.com/intuit/gitdetect/filerepo/scanner"
	"github.com/intuit/gitdetect/rule/config"
	"io"
	"log"
	"os"
	"path"
	"strings"
)

const (
	//LOG_FILE log filename
	LOG_FILE = "gitdetect.log"
)

//CLI parameter names
const (
	CLI_ARG_CONFIG_FILENAME          = "rule-config"
	CLI_ARG_GIT_ACCESS_TOKEN         = "access-token"
	CLI_ARG_OUTPUT_DIR               = "output-dir"
	CLI_ARG_GIT_HOSTNAME             = "github-hostname"
	CLI_ARG_GIT_REPO_NAME            = "repo-name"
	CLI_ARG_GIT_LAST_MODIFIED_CUTOFF = "last-modified-cutoff"
	CLI_ARG_LOCAL_SCAN_DIR           = "local-scan-dir"
	CLI_ARG_DEBUG_PRINT_SECRETS      = "debug-print-secrets"
)

//ScanParameters captures CLI parameters
type ScanParameters struct {
	configFilename         string
	accessToken            string
	outputDir              string
	githubHostname         string
	repoName               string
	lastModifiedScanCutoff int //days
	localScanDir           string
	debugPrintSecrets      bool
}

//main gitdetect CLI entry point
func main() {

	doMain(os.Args[1:])
}

func doMain(cliArguments []string) (defectReport *defect.Report, err error) {

	defer func() {
		if r := recover(); r != nil {
			switch r.(type) {
			case error:
				log.Fatal(r.(error).Error())
			default:
				log.Fatal("Unknown error")

			}
		}
	}()

	scanParameters, err := initializeScanParameters(cliArguments)

	if err != nil {
		log.Printf("Error initializing parameters %s", err.Error())
		return
	}

	scanner.DebugPrintSecrets = scanParameters.debugPrintSecrets

	defectReport, err = startScanning(scanParameters)

	if err == nil {
		log.Printf("Total number of defects: -%d-\n", defectReport.DefectCount)
		defectReport.Save()
	} else {
		log.Printf("Scanning failed, error: %s", err.Error())
	}

	return
}

func startScanning(scanParameters ScanParameters) (*defect.Report, error) {

	initializeLog(scanParameters.outputDir)
	defectReport := defect.NewDefectReport(scanParameters.outputDir)
	repoScanner := initializeFileRepository(scanParameters)

	return defectReport, repoScanner.Scan(defectReport)

}

//Returns either a GithubFileRepository or LocalFileRepository FileRepository implementation.
func initializeFileRepository(scanParameters ScanParameters) filerepo.FileRepository {
	secretDetectionRules := config.LoadDetectionRules(scanParameters.configFilename)
	fileScanner := scanner.FileScanner{RootDir: scanParameters.localScanDir, Rules: secretDetectionRules.Rules}

	if scanParameters.localScanDir == "" {
		return github.NewGithubFileRepository(scanParameters.githubHostname, scanParameters.accessToken, scanParameters.lastModifiedScanCutoff, scanParameters.repoName, scanParameters.outputDir, fileScanner)
	}

	return localfs.NewLocalFileRepository(fileScanner)
}

func initializeLog(outputDir string) {

	logFileName := path.Join(outputDir, LOG_FILE)
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}

	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
}

func initializeScanParameters(cliArguments []string) (scanParameters ScanParameters, err error) {

	flagset := flag.NewFlagSet("commandLine", flag.ExitOnError)

	flagset.StringVar(&scanParameters.configFilename, CLI_ARG_CONFIG_FILENAME, "", "Full path name of the detection rule configuration file.")
	flagset.StringVar(&scanParameters.accessToken, CLI_ARG_GIT_ACCESS_TOKEN, "", "github access token.")
	flagset.StringVar(&scanParameters.outputDir, CLI_ARG_OUTPUT_DIR, "", "working dir and report genaration dir.")
	flagset.StringVar(&scanParameters.githubHostname, CLI_ARG_GIT_HOSTNAME, "github.com", "github url hostname")
	flagset.StringVar(&scanParameters.repoName, CLI_ARG_GIT_REPO_NAME, "", "Fully qualified repo name in the format <owner>/<name>/[<branch>] e.g. my-org/my-proj for the default branch or my-org/my-proj/my-feature-branch. Leave blank for a full github scan.")
	flagset.IntVar(&scanParameters.lastModifiedScanCutoff, CLI_ARG_GIT_LAST_MODIFIED_CUTOFF, 0, "The repository will not be scanned unless it was modified in the last number of days specified here. 0 indicates scan always.")
	flagset.StringVar(&scanParameters.localScanDir, CLI_ARG_LOCAL_SCAN_DIR, "", "The local directory path to scan.  When set, github related options are ignored.")
	flagset.BoolVar(&scanParameters.debugPrintSecrets, CLI_ARG_DEBUG_PRINT_SECRETS, false, "Print detected secrets to standard output.  Use with discretion.")

	err = flagset.Parse(cliArguments)
	if err != nil {
		err = errors.New("Failed parsing flagset " + err.Error())
		return
	}

	if scanParameters.outputDir == "" {
		scanParameters.outputDir, err = os.Getwd()
		if err != nil {
			err = errors.New("Failed to initialize output directory " + err.Error())
			return
		}
	} else {
		if _, err = os.Stat(scanParameters.outputDir); os.IsNotExist(err) {

			err = errors.New("Output directory doesn't exist " + err.Error())
			return
		}
	}

	if scanParameters.configFilename == "" {
		err = errors.New("Configuration file not specified")
		return
	}

	if scanParameters.localScanDir == "" {

		if scanParameters.accessToken == "" {
			err = errors.New("Access Token not specified")
			return
		}

		if scanParameters.repoName != "" {
			repoOwnerNameBranch := strings.Split(scanParameters.repoName, "/")
			if len(repoOwnerNameBranch) != 2 && len(repoOwnerNameBranch) != 3 {
				err = errors.New("Invalid parameter, repo-name must be in the format <owner>/<name> ")
				return
			}
		}

		if scanParameters.lastModifiedScanCutoff < 0 {
			err = errors.New("Invalid parameter, last-modified-cutoff cannot be less than 0")
			return
		}

		if scanParameters.lastModifiedScanCutoff > 0 {
			log.Printf("Scanning only repositories that were updated in the last %d days", scanParameters.lastModifiedScanCutoff)
		}
	}
	return
}
