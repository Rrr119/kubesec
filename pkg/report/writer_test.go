package report

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/controlplaneio/kubesec/v2/pkg/ruler"
)

func TestSARIFTemplateIncludesRemediationMetadata(t *testing.T) {
	templateBytes, err := os.ReadFile("../../templates/sarif.tpl")
	if err != nil {
		t.Fatal(err)
	}

	rule := ruler.RuleRef{
		ID:            "Privileged",
		Selector:      "containers[] .securityContext .privileged == true",
		Reason:        "Privileged containers can allow almost completely unrestricted host access",
		Points:        -30,
		Priority:      ruler.PriorityImmediate,
		PriorityLabel: "P0",
		Impact:        ruler.ImpactHost,
		ImpactScore:   99,
		Field:         "spec.containers[*].securityContext.privileged",
		Fields:        []string{"spec.containers[*].securityContext.privileged"},
		Explanation:   "A privileged container can escape to the node.",
		Remediation:   "Set securityContext.privileged to false.",
		Category:      "critical",
	}

	report := ruler.Report{
		Object:   "Pod/example.default",
		Valid:    true,
		FileName: "pod.yaml",
		Rules:    []ruler.RuleRef{rule},
		Score:    -30,
		Scoring: ruler.RuleScoring{
			Critical:    []ruler.RuleRef{rule},
			Remediation: []ruler.RuleRef{rule},
		},
	}

	var output bytes.Buffer
	if err := WriteReports("template", &output, []ruler.Report{report}, string(templateBytes)); err != nil {
		t.Fatal(err)
	}

	var sarif struct {
		Runs []struct {
			Results []struct {
				Message struct {
					Properties map[string]string `json:"properties"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(output.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, output.String())
	}

	properties := sarif.Runs[0].Results[0].Message.Properties
	if properties["priorityLabel"] != "P0" {
		t.Fatalf("priority label missing from SARIF properties: %v", properties)
	}
	if properties["field"] != rule.Field {
		t.Fatalf("field missing from SARIF properties: %v", properties)
	}
	if properties["remediation"] != rule.Remediation {
		t.Fatalf("remediation missing from SARIF properties: %v", properties)
	}
}
