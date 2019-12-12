package filerepo

//package filerepo declares the FileRepository interface.  An implementation uses the Scan method to populate a DefectReport with secrets found in files.

import (
	"github.com/intuit/gitdetect/defect"
)

//FileRepository Integration with new type of file source should implement this type
type FileRepository interface {
	//Scan should periodically call defectReport.Save() for long running scans.  This allows viewing of partial results until the scan is complete.
	Scan(defectReport *defect.Report) error
}
