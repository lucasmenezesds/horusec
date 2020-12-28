// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flawfinder

import (
<<<<<<< HEAD
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/c"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
=======
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	flawfinderEntities "github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/c/flawfinder/entities"
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
	"github.com/gocarina/gocsv"
)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
<<<<<<< HEAD
	if f.ToolIsToIgnore(tools.Flawfinder) {
=======
	if f.ToolIsToIgnore(tools.Flawfinder) || f.IsDockerDisabled() {
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.Flawfinder.ToString(), logger.DebugLevel)
		return
	}

<<<<<<< HEAD
	err := f.startFlawFinder(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.Flawfinder, projectSubPath)
}

func (f *Formatter) startFlawFinder(projectSubPath string) error {
=======
	f.SetAnalysisError(f.startFlawfinder(projectSubPath), tools.Flawfinder, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Flawfinder)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startFlawfinder(projectSubPath string) error {
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Flawfinder)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
<<<<<<< HEAD
		f.SetAnalysisError(err)
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Flawfinder)
=======
		return err
	}

>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
<<<<<<< HEAD
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Flawfinder),
		Language: languages.C,
	}
}

func (f *Formatter) parseOutput(output string) error {
	var results []c.Result

	if err := gocsv.UnmarshalString(output, &results); err != nil {
		f.SetAnalysisError(fmt.Errorf("{HORUSEC_CLI} Error %s", output))
		return err
	}

	f.appendResults(results)
	return nil
}

func (f *Formatter) appendResults(results []c.Result) {
	for index := range results {
		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
				Vulnerability: *f.setVulnerabilityData(results, index),
			})
	}
}

func (f *Formatter) setVulnerabilityData(results []c.Result, index int) *horusec.Vulnerability {
=======
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Flawfinder),
		Language: languages.C,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.Flawfinder].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) parseOutput(output string) error {
	var results []flawfinderEntities.Result

	if err := gocsv.UnmarshalString(output, &results); err != nil {
		return err
	}

	for index := range results {
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(results, index))
	}

	return nil
}

func (f *Formatter) setVulnerabilityData(results []flawfinderEntities.Result, index int) *horusec.Vulnerability {
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = results[index].GetSeverity()
	vulnerability.Details = results[index].GetDetails()
	vulnerability.Line = results[index].Line
	vulnerability.Column = results[index].Column
	vulnerability.Code = f.GetCodeWithMaxCharacters(results[index].Context, 0)
	vulnerability.File = results[index].GetFilename()
<<<<<<< HEAD
	vulnerability = vulnhash.Bind(vulnerability)

	return f.setCommitAuthor(vulnerability)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, f.getFilePathFromPackageName(vulnerability.File))

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitDate = commitAuthor.Date
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitMessage = commitAuthor.Message

	return vulnerability
=======
	vulnerability = hash.Bind(vulnerability)
	return f.SetCommitAuthor(vulnerability)
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Flawfinder
	vulnerabilitySeverity.Language = languages.C
	return vulnerabilitySeverity
}
<<<<<<< HEAD

func (f *Formatter) getFilePathFromPackageName(filePath string) string {
	return fileUtil.GetPathIntoFilename(filePath,
		fmt.Sprintf("%s/", f.GetConfigProjectPath()))
}
=======
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
