package defect

import (
	"github.com/intuit/gitdetect/secret"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"path/filepath"
)

//Package defect provides the structures used to document detected secrets in the process output file.

//File containing secret
type File struct {
	Filename string
}

//Defect represents a unique secret combination of a file and a unique secret
type Defect struct {
	Lines          []int
	secretID       string
	Tag            string
	AdditionalInfo string `yaml:"additional-info,omitempty"`
}

//Report fully documents detected secrets and is written to the final output file
type Report struct {
	Repositories map[FileRepo]FileDefects
	DefectCount  int
	outputDir    string
}

//FileRepo documents the FileRepository scanned
type FileRepo struct {
	ID       int64  `yaml:",omitempty"`          //Intialized for GithubFileRepository
	Org      string `yaml:",omitempty"`          //Intialized for GithubFileRepository
	Name     string `yaml:",omitempty"`          //Intialized for GithubFileRepository
	Branch   string `yaml:",omitempty"`          //Intialized for GithubFileRepository
	Head     string `yaml:",omitempty"`          //Intialized for GithubFileRepository
	LastPush string `yaml:"last-push,omitempty"` //Intialized for GithubFileRepository
	LocalDir string `yaml:",omitempty"`          //Intialized for LocalFileRepository
}

//FileDefects is the mapping of files
type FileDefects struct {
	Defects map[File][]*Defect
}

//NewFileDefects allocates FileDefects structure
func NewFileDefects() FileDefects {
	return FileDefects{
		Defects: make(map[File][]*Defect),
	}
}

//AddInstance adds a new Defect structure when secret is the first occurrence detected in fileName.  If secret is not the first occurrence found in fileName the Defect is modified
// to inlcude the additional line number where the secret was again detected.
func (this *FileDefects) AddInstance(fileName string, secret secret.Secret) (defectInstance *Defect, newDefect bool) {

	file := File{Filename: fileName}
	newDefect = true

	if fileDefects, ok := this.Defects[file]; ok {
		for index, defectInstance := range fileDefects {
			if defectInstance.secretID == secret.ID {
				newDefect = false
				defectInstance.Lines = append(defectInstance.Lines, secret.LineNumber)
				fileDefects[index] = defectInstance
				break
			}
		}
	} else {
		this.Defects[file] = []*Defect{}
	}

	if newDefect {
		defectInstance = &Defect{
			secretID: secret.ID,
			Lines:    []int{secret.LineNumber},
			Tag:      secret.Rule.Tag,
		}
		this.Defects[file] = append(this.Defects[file], defectInstance)
	}

	return
}

//NewDefectReport initialzied a DefectReport structure used to maintain and report detected secrets
func NewDefectReport(outputDir string) *Report {
	return &Report{
		Repositories: make(map[FileRepo]FileDefects),
		outputDir:    outputDir,
	}

}

//AddDefects adds a FileDefect collection to currentRepo
func (this *Report) AddDefects(currentRepo FileRepo, fileDefects FileDefects) {
	this.Repositories[currentRepo] = fileDefects
}

//Save outputs DefectReport to defectReport.yaml in the output directory specified on the command line
func (this *Report) Save() {

	reportFileName := filepath.Join(this.outputDir, "defectReport.yaml")
	yaml, err := yaml.Marshal(this)
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	if err := ioutil.WriteFile(reportFileName, yaml, 0644); err != nil {
		log.Fatal(err)
	}
}

//ReduceAndExploit consolidates instances of the same secret and executes the optional Expoloit function specified in the configuration rule used to detect the Value.
func (this *Report) ReduceAndExploit(secrets []secret.Secret, scanRoot string) FileDefects {

	fileDefects := NewFileDefects()

	for _, secret := range secrets {

		relativeFileName := GetRelativeFilename(secret.FileName, scanRoot)

		if defect, newDefect := fileDefects.AddInstance(relativeFileName, secret); newDefect {
			this.DefectCount++
			secretInfo := secret.Exploit()
			defect.AdditionalInfo = secretInfo

		}
	}

	return fileDefects
}

//GetRelativeFilename returns filename relative to scan root directory
func GetRelativeFilename(fileName string, rootDir string) string {
	return fileName[len(rootDir)+1:]
}
