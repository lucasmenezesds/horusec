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

package phpcs

import (
	"encoding/json"
<<<<<<< HEAD
	"fmt"
	phpEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/php/phpcs"
=======

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/php/phpcs/entities"

>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
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
	if f.ToolIsToIgnore(tools.PhpCS) {
=======
	if f.ToolIsToIgnore(tools.PhpCS) || f.IsDockerDisabled() {
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.PhpCS.ToString(), logger.DebugLevel)
		return
	}

<<<<<<< HEAD
	err := f.startPhpCs(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.PhpCS, projectSubPath)
=======
	f.SetAnalysisError(f.startPhpCs(projectSubPath), tools.PhpCS, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.PhpCS)
	f.SetToolFinishedAnalysis()
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
}

func (f *Formatter) startPhpCs(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.PhpCS)

<<<<<<< HEAD
	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.PhpCS)
	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.PhpCS),
		Language: languages.PHP,
	}
=======
	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.PhpCS),
		Language: languages.PHP,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.PhpCS].ImagePath, ImageName, ImageTag)
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
}

func (f *Formatter) parseOutput(output string) error {
	var results map[string]interface{}

	if err := json.Unmarshal([]byte(output), &results); err != nil {
<<<<<<< HEAD
		f.SetAnalysisError(fmt.Errorf("{HORUSEC_CLI} Error %s", output))
=======
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
		return err
	}

	f.parseResults(results)
	return nil
}

func (f *Formatter) parseResults(results map[string]interface{}) {
	if results != nil {
		files := results["files"]
		for filepath, result := range files.(map[string]interface{}) {
			f.parseMessages(filepath, result)
		}
	}
}

func (f *Formatter) parseMessages(filepath string, result interface{}) {
	for _, message := range f.parseToResult(result).Messages {
<<<<<<< HEAD
		f.appendResults(filepath, message)
	}
}

func (f *Formatter) appendResults(filepath string, message phpEntities.Message) {
	if message.IsValidMessage() {
		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
				Vulnerability: *f.setVulnerabilityData(filepath, message),
			})
	}
}

func (f *Formatter) setVulnerabilityData(filepath string, result phpEntities.Message) *horusec.Vulnerability {
=======
		if message.IsValidMessage() {
			f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(filepath, message))
		}
	}
}

func (f *Formatter) setVulnerabilityData(filepath string, result entities.Message) *horusec.Vulnerability {
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = severity.Info
	vulnerability.Details = result.Message
	vulnerability.Line = result.GetLine()
	vulnerability.Column = result.GetColumn()
	vulnerability.File = f.RemoveSrcFolderFromPath(filepath)
	vulnerability = vulnhash.Bind(vulnerability)
<<<<<<< HEAD

	return f.setCommitAuthor(vulnerability)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, vulnerability.File)

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitDate = commitAuthor.Date
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitMessage = commitAuthor.Message

	return vulnerability
=======
	return f.SetCommitAuthor(vulnerability)
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.PhpCS
	vulnerabilitySeverity.Language = languages.PHP
	return vulnerabilitySeverity
}

<<<<<<< HEAD
func (f *Formatter) parseToResult(messageInterface interface{}) *phpEntities.Result {
	var result *phpEntities.Result
=======
func (f *Formatter) parseToResult(messageInterface interface{}) *entities.Result {
	var result *entities.Result
>>>>>>> 538d56d31687b4cbea77d421b2708a24be39bbb7

	bytes, _ := json.Marshal(messageInterface)
	_ = json.Unmarshal(bytes, &result)

	return result
}
