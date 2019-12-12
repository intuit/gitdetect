package localfs

//package localfs is used to interface with the local filesystem as a FileRepository source.

import (
	"github.com/intuit/gitdetect/defect"
	"github.com/intuit/gitdetect/filerepo/scanner"
	"log"
	"os"
)

//LocalFileRepository represents a local directory file source
type LocalFileRepository struct {
	fileScanner scanner.FileScanner
}

//NewLocalFileRepository return new LocalFileRepository
func NewLocalFileRepository(fileScanner scanner.FileScanner) *LocalFileRepository {
	return &LocalFileRepository{fileScanner: fileScanner}
}

//Scan scan local directory
func (this *LocalFileRepository) Scan(defectReport *defect.Report) (err error) {

	log.Println("Starting local scan of " + this.fileScanner.RootDir)

	_, err = os.Stat(this.fileScanner.RootDir)

	if err != nil {
		return
	}

	repo := defect.FileRepo{LocalDir: this.fileScanner.RootDir}

	repoSecrets := this.fileScanner.Scan()
	if len(repoSecrets) > 0 {
		defects := defectReport.ReduceAndExploit(repoSecrets, this.fileScanner.RootDir)
		defectReport.AddDefects(repo, defects)
	}

	return

}
