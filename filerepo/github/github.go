package github

//Package github is used to interface with a github server host as the FileRepository source.  Github repositories are downloaded as zip archives and scanned on the local filesystem.

import (
	"github.com/intuit/gitdetect/defect"
	"golang.org/x/net/context"

	"bytes"
	"fmt"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/intuit/gitdetect/filerepo/scanner"
	"github.com/intuit/gitdetect/secret"
)

//FileRepository represents a Github FileRepository source
type FileRepository struct {
	accessToken            string
	lastModifiedScanCutoff time.Time
	repoOwner              string //set if we're scanning a distinct repository
	repoName               string //set if we're scanning a distinct repository
	repoBranch             string //optionally set if we're scanning a distinct repository
	gitClient              *github.Client
	fileScanner            scanner.FileScanner
	rootDir                string
	scannedReposCounter    int
	hostname               string
}

//NewGithubFileRepository returns a new GithubFileRepository structure used to scan any number of repositories on the given github host.
func NewGithubFileRepository(githubHostname string, accessToken string, lastModifiedScanCutoff int, repoNameFQ string, workingDir string, fileScanner scanner.FileScanner) *FileRepository {

	githubRepository := FileRepository{hostname: githubHostname, accessToken: accessToken, fileScanner: fileScanner, rootDir: workingDir}

	if repoNameFQ != "" {
		repoNameArray := strings.Split(repoNameFQ, "/")
		githubRepository.repoOwner = repoNameArray[0]
		githubRepository.repoName = repoNameArray[1]
		if len(repoNameArray) == 3 {
			githubRepository.repoBranch = repoNameArray[2]
		}
	}

	if lastModifiedScanCutoff > 0 {
		githubRepository.lastModifiedScanCutoff = time.Now().AddDate(0, 0, -lastModifiedScanCutoff)
	}

	githubRepository.gitClient = githubRepository.initClient()

	return &githubRepository
}

//Scan scans this repoOwner/repoBranch when repoOwner & repoBranch are set.  When not set, all repositories on this hostname accessable by this accessToken are scanned
func (this *FileRepository) Scan(defectReport *defect.Report) (err error) {

	if this.repoName != "" {
		var repository *github.Repository
		repository, _, err = this.gitClient.Repositories.Get(context.Background(), this.repoOwner, this.repoName)
		if err == nil {
			err = this.scanRepo(repository, defectReport)
		}
	} else {
		err = this.scanRepos(defectReport)
		log.Printf("Total number of github repositories scanned: -%d-\n", this.scannedReposCounter)
	}

	return
}

func (this *FileRepository) scanRepos(defectReport *defect.Report) error {

	opt := &github.RepositoryListAllOptions{
		Since: 0,
	}
	gClient := this.gitClient

	for {
		repos, _, err := gClient.Repositories.ListAll(context.Background(), opt)

		if err != nil {
			return err
		}
		if len(repos) == 0 {
			break
		}

		for _, repoElement := range repos {

			//this repoElement will have more meta data than the one being paged through
			repoElement, _, err = gClient.Repositories.GetByID(context.Background(), repoElement.GetID())
			if err != nil {
				log.Println("ERROR: failed getting detailed repository data for " + repoElement.GetName() + ", skipping this repository.")
				continue
			}

			//If this is an incremental run WRT repository update activity, check last update for this repository
			if !repoElement.GetPushedAt().After(this.lastModifiedScanCutoff) {
				continue
			}

			err = this.scanRepo(repoElement, defectReport)
			if err != nil {
				log.Println("ERROR: scan failed on " + repoElement.GetName() + ", skipping this repository.")
				continue
			}
		}

		opt.Since = repos[len(repos)-1].GetID()
	}

	return nil
}

func (this *FileRepository) scanRepo(repository *github.Repository, defectReport *defect.Report) (err error) {

	log.Printf("scanning repo id %d %s", repository.GetID(), repository.GetName())
	localRepoDir, err := this.downloadRepoArchive(repository.GetArchiveURL(), repository.GetName(), this.repoBranch)

	if err != nil {
		err = fmt.Errorf("Error downloading %s, %s, skipping this repository", repository.GetArchiveURL(), err.Error())
		return
	}

	repoSecrets := this.scanFiles(localRepoDir)
	this.scannedReposCounter++
	if len(repoSecrets) > 0 {
		defects := defectReport.ReduceAndExploit(repoSecrets, localRepoDir)
		repoDetails := this.getRepoDetails(repository)
		defectReport.AddDefects(repoDetails, defects)
		defectReport.Save()
	}
	os.RemoveAll(localRepoDir)

	return
}

func (this *FileRepository) getRepoDetails(repoElement *github.Repository) (repoReport defect.FileRepo) {
	//Basic data available from repository handle
	repoReport = defect.FileRepo{
		Name:     repoElement.GetName(),
		ID:       repoElement.GetID(),
		Org:      repoElement.GetOwner().GetLogin(),
		Branch:   repoElement.GetDefaultBranch(),
		LastPush: repoElement.GetPushedAt().Time.Format("2006-01-02"),
	}

	branch, _, err := this.gitClient.Repositories.GetBranch(context.Background(), repoElement.GetOwner().GetLogin(), repoElement.GetName(), repoElement.GetDefaultBranch())
	if err != nil {
		log.Printf("Failed getting head commit id for repository %s", repoElement.GetName())
		return
	}
	repoReport.Head = branch.GetCommit().GetSHA()

	return
}

func (this *FileRepository) initClient() *github.Client {

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: this.accessToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	gClient := github.NewClient(tc)

	githubURL := url.URL{
		Scheme: "https",
		Host:   this.hostname,
		Path:   "/api/v3/",
	}
	gClient.BaseURL = &githubURL
	return gClient
}

func (this *FileRepository) downloadRepoArchive(archiveURL string, repoName string, repoBranch string) (string, error) {

	archiveURL = strings.Replace(archiveURL, "{archive_format}{/ref}", "zipball/"+repoBranch, 1)

	response, err := http.Get(archiveURL + "?access_token=" + this.accessToken)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()
	outputBuffer, err := ioutil.ReadAll(response.Body)
	//_, err = io.Copy(output, response.Body)

	if err != nil {
		return "", err
	}

	newReader := bytes.NewReader(outputBuffer)

	rootDir, err := Unzip(newReader, int64(len(outputBuffer)), this.rootDir+string(filepath.Separator))

	localRepoDir := filepath.Join(this.rootDir, rootDir)

	return localRepoDir, err
}

func (this *FileRepository) scanFiles(localDir string) (repoSecrets []secret.Secret) {

	this.fileScanner.RootDir = localDir
	return this.fileScanner.Scan()

}
