package ruler

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"go.uber.org/zap"
)

const podGuidanceManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: guidance-test
spec:
  hostAliases:
  - ip: 203.0.113.10
    hostnames:
    - example.internal
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      seccompProfile:
        type: Unconfined
`

func newTestRuleset(t *testing.T) *Ruleset {
	t.Helper()

	ruleset, err := NewRuleset(zap.NewNop().Sugar())
	if err != nil {
		t.Fatal(err)
	}
	return ruleset
}

func runGuidanceManifest(t *testing.T, ruleset *Ruleset, manifest string) Report {
	t.Helper()

	config := NewDefaultSchemaConfig()
	config.DisableValidation = true

	reports, err := ruleset.Run("manifest.yaml", []byte(manifest), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	return reports[0]
}

func findRuleRef(rules []RuleRef, id string) (RuleRef, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return RuleRef{}, false
}

func TestRuleGuidanceIsComplete(t *testing.T) {
	ruleset := newTestRuleset(t)

	for _, rule := range ruleset.Rules {
		if _, ok := ruleGuidanceByID[rule.ID]; !ok {
			t.Errorf("%s: no rule-specific guidance configured", rule.ID)
		}
		if rule.Priority < PriorityImmediate || rule.Priority > PriorityLow {
			t.Errorf("%s: priority %d is outside %d..%d", rule.ID, rule.Priority, PriorityImmediate, PriorityLow)
		}
		if rule.PriorityLabel != priorityLabel(rule.Priority) {
			t.Errorf("%s: priority label %q does not match priority %d", rule.ID, rule.PriorityLabel, rule.Priority)
		}
		if rule.Impact == "" || rule.ImpactScore <= 0 {
			t.Errorf("%s: impact metadata is incomplete", rule.ID)
		}
		if len(rule.Fields) == 0 {
			t.Errorf("%s: no concrete field paths configured", rule.ID)
		}
		for _, field := range rule.Fields {
			if strings.TrimSpace(field) == "" {
				t.Errorf("%s: contains an empty field path", rule.ID)
			}
		}
		if strings.TrimSpace(rule.Explanation) == "" {
			t.Errorf("%s: no explanation configured", rule.ID)
		}
		if strings.TrimSpace(rule.Remediation) == "" {
			t.Errorf("%s: no remediation configured", rule.ID)
		}
	}
}

func TestRemediationPriorityMatchesHumanChecklist(t *testing.T) {
	expected := []string{
		"BindingsToSystemAnonymous",
		"Privileged",
		"CapSysAdmin",
		"DockerSock",
		"ProcMount",
		"HostPID",
		"HostIPC",
		"HostNetwork",
		"AllowPrivilegeEscalation",
		"SecretsAsEnvironmentVariables",
		"SeccompUnconfined",
		"ApparmorUnconfined",
		"RunAsNonRoot",
		"AutomountServiceAccountToken",
		"ServiceAccountName",
		"ReadOnlyRootFilesystem",
		"HostAliases",
		"SeccompAny",
		"ApparmorAny",
		"CapDropAll",
	}

	ruleset := newTestRuleset(t)
	byID := make(map[string]Rule, len(ruleset.Rules))
	for _, rule := range ruleset.Rules {
		byID[rule.ID] = rule
	}

	actual := make([]RuleRef, 0, len(expected))
	for _, id := range expected {
		rule, ok := byID[id]
		if !ok {
			t.Fatalf("checklist rule %s is missing", id)
		}
		actual = append(actual, RuleRef{
			ID:          rule.ID,
			Priority:    rule.Priority,
			ImpactScore: rule.ImpactScore,
			Points:      rule.Points,
			Category:    "critical",
		})
	}

	sort.Sort(RemediationOrder(actual))
	for i := range expected {
		if actual[i].ID != expected[i] {
			t.Fatalf("priority item %d: got %s, want %s", i+1, actual[i].ID, expected[i])
		}
	}
}

func TestRemediationAddsImpactOrderAndKeepsLegacyOrder(t *testing.T) {
	ruleset := newTestRuleset(t)
	report := runGuidanceManifest(t, ruleset, podGuidanceManifest)

	if len(report.Scoring.Critical) != 2 {
		t.Fatalf("got %d critical rules, want 2", len(report.Scoring.Critical))
	}
	if report.Scoring.Critical[0].ID != "HostAliases" || report.Scoring.Critical[1].ID != "SeccompUnconfined" {
		t.Fatalf("legacy critical order changed: got %s then %s", report.Scoring.Critical[0].ID, report.Scoring.Critical[1].ID)
	}
	if report.Scoring.Critical[0].Order == 0 || report.Scoring.Critical[1].Order == 0 {
		t.Fatal("legacy critical items do not expose their impact order")
	}
	if report.Scoring.Critical[1].Order >= report.Scoring.Critical[0].Order {
		t.Fatalf("impact order metadata wrong: HostAliases=%d SeccompUnconfined=%d", report.Scoring.Critical[0].Order, report.Scoring.Critical[1].Order)
	}

	seccompIndex := -1
	hostAliasesIndex := -1
	for i, item := range report.Scoring.Remediation {
		if item.ID == "SeccompUnconfined" {
			seccompIndex = i
		}
		if item.ID == "HostAliases" {
			hostAliasesIndex = i
		}
	}
	if seccompIndex < 0 || hostAliasesIndex < 0 {
		t.Fatal("expected critical rules are missing from remediation list")
	}
	if seccompIndex >= hostAliasesIndex {
		t.Fatalf("impact order wrong: SeccompUnconfined index %d, HostAliases index %d", seccompIndex, hostAliasesIndex)
	}
	if report.Scoring.Remediation[seccompIndex].Order != seccompIndex+1 {
		t.Fatalf("remediation order was not numbered: item %s has order %d", report.Scoring.Remediation[seccompIndex].ID, report.Scoring.Remediation[seccompIndex].Order)
	}

	for _, item := range report.Scoring.Remediation {
		if item.Priority == 0 || item.PriorityLabel == "" || item.Impact == "" {
			t.Errorf("%s: priority/impact metadata missing", item.ID)
		}
		if item.Field == "" || len(item.Fields) == 0 {
			t.Errorf("%s: concrete field paths missing", item.ID)
		}
		if item.Explanation == "" || item.Remediation == "" {
			t.Errorf("%s: explanation or remediation missing", item.ID)
		}
	}

	seccomp, ok := findRuleRef(report.Scoring.Remediation, "SeccompUnconfined")
	if !ok {
		t.Fatal("SeccompUnconfined missing from remediation list")
	}
	foundContainerField := false
	for _, field := range seccomp.Fields {
		if field == "spec.containers[*].securityContext.seccompProfile.type" {
			foundContainerField = true
		}
	}
	if !foundContainerField {
		t.Fatalf("SeccompUnconfined fields do not identify the container field: %v", seccomp.Fields)
	}
}

func TestRuleFieldsAreRenderedForResourceKind(t *testing.T) {
	tests := []struct {
		name      string
		manifest  string
		ruleID    string
		wantField string
	}{
		{
			name: "deployment pod template",
			manifest: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
`,
			ruleID:    "Privileged",
			wantField: "spec.template.spec.containers[*].securityContext.privileged",
		},
		{
			name: "cronjob pod template",
			manifest: `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: job
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: app
            image: nginx
            env:
            - name: TOKEN
              valueFrom:
                secretKeyRef:
                  name: token
                  key: token
`,
			ruleID:    "SecretsAsEnvironmentVariables",
			wantField: "spec.jobTemplate.spec.template.spec.containers[*].env[*].valueFrom.secretKeyRef",
		},
		{
			name: "role binding subject",
			manifest: `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: anonymous
subjects:
- kind: User
  name: system:anonymous
roleRef:
  kind: Role
  name: reader
  apiGroup: rbac.authorization.k8s.io
`,
			ruleID:    "BindingsToSystemAnonymous",
			wantField: "subjects[*].name",
		},
		{
			name: "statefulset volume claim template",
			manifest: `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  serviceName: db
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
      - name: db
        image: postgres
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes:
      - ReadWriteMany
`,
			ruleID:    "VolumeClaimAccessModeReadWriteOnce",
			wantField: "spec.volumeClaimTemplates[*].spec.accessModes",
		},
	}

	ruleset := newTestRuleset(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := runGuidanceManifest(t, ruleset, tt.manifest)
			item, ok := findRuleRef(report.Scoring.Remediation, tt.ruleID)
			if !ok {
				t.Fatalf("%s not found in remediation list", tt.ruleID)
			}
			if item.Field != tt.wantField {
				t.Fatalf("field: got %q, want %q", item.Field, tt.wantField)
			}
			if item.Remediation == "" || item.Explanation == "" {
				t.Fatal("remediation or explanation is empty")
			}
		})
	}
}

func TestJSONOutputRemainsBackwardCompatible(t *testing.T) {
	ruleset := newTestRuleset(t)
	report := runGuidanceManifest(t, ruleset, podGuidanceManifest)

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if _, ok := decoded["score"]; !ok {
		t.Fatal("legacy score field is missing")
	}
	scoring, ok := decoded["scoring"].(map[string]interface{})
	if !ok {
		t.Fatal("legacy scoring object is missing")
	}
	for _, legacyKey := range []string{"critical", "advise", "remediation"} {
		if _, ok := scoring[legacyKey]; !ok {
			t.Fatalf("scoring.%s is missing", legacyKey)
		}
	}

	critical := scoring["critical"].([]interface{})
	first := critical[0].(map[string]interface{})
	for _, legacyKey := range []string{"id", "selector", "reason", "points"} {
		if _, ok := first[legacyKey]; !ok {
			t.Fatalf("legacy critical item field %s is missing", legacyKey)
		}
	}
	for _, newKey := range []string{"priority", "priorityLabel", "impact", "field", "fields", "explanation", "remediation"} {
		if _, ok := first[newKey]; !ok {
			t.Fatalf("new critical item field %s is missing", newKey)
		}
	}
}
