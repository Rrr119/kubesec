package ruler

import "fmt"

const (
	PriorityImmediate = 1
	PriorityHigh      = 2
	PriorityMedium    = 3
	PriorityLow       = 4
)

const (
	ImpactHost         = "host"
	ImpactCluster      = "cluster"
	ImpactWorkload     = "workload"
	ImpactContainer    = "container"
	ImpactAvailability = "availability"
)

// ruleGuidance contains the operational context that is not part of the
// numeric score. The field paths use $podSpec as a placeholder so the same
// guidance can be rendered for Pods, Deployments, StatefulSets and DaemonSets.
type ruleGuidance struct {
	Priority    int
	Impact      string
	ImpactScore int
	Fields      []string
	Explanation string
	Remediation string
}

func priorityLabel(priority int) string {
	if priority < PriorityImmediate {
		priority = PriorityImmediate
	}
	return fmt.Sprintf("P%d", priority-1)
}

func applyRuleGuidance(rule *Rule) {
	guidance, ok := ruleGuidanceByID[rule.ID]
	if !ok {
		rule.Priority = defaultPriority(rule)
		rule.PriorityLabel = priorityLabel(rule.Priority)
		rule.Impact = ImpactWorkload
		rule.ImpactScore = rule.Priority * 10
		rule.Fields = []string{rule.Selector}
		rule.Explanation = rule.Reason
		rule.Remediation = "Review the selector and update the manifest so the rule passes."
		return
	}

	rule.Priority = guidance.Priority
	rule.PriorityLabel = priorityLabel(guidance.Priority)
	rule.Impact = guidance.Impact
	rule.ImpactScore = guidance.ImpactScore
	rule.Fields = append([]string(nil), guidance.Fields...)
	rule.Explanation = guidance.Explanation
	rule.Remediation = guidance.Remediation
}

func defaultPriority(rule *Rule) int {
	switch {
	case rule.Points <= -30:
		return PriorityImmediate
	case rule.Points < 0:
		return PriorityHigh
	case rule.Advise >= 10:
		return PriorityHigh
	case rule.Advise > 0 || rule.Points > 0:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

var ruleGuidanceByID = map[string]ruleGuidance{
	"BindingsToSystemAnonymous": {
		Priority:    PriorityImmediate,
		Impact:      ImpactCluster,
		ImpactScore: 100,
		Fields:      []string{"subjects[*].name"},
		Explanation: "A RoleBinding or ClusterRoleBinding to system:anonymous lets unauthenticated callers use every permission granted by the bound role, potentially across the whole cluster.",
		Remediation: "Remove the system:anonymous subject and bind only named users, groups or service accounts that require the role.",
	},
	"Privileged": {
		Priority:    PriorityImmediate,
		Impact:      ImpactHost,
		ImpactScore: 99,
		Fields: []string{
			"$podSpec.containers[*].securityContext.privileged",
			"$podSpec.initContainers[*].securityContext.privileged",
			"$podSpec.ephemeralContainers[*].securityContext.privileged",
		},
		Explanation: "A privileged container receives nearly all host capabilities and device access, so a compromised process can usually escape the container and control the node.",
		Remediation: "Set securityContext.privileged to false or remove it, then grant only the individual capabilities the workload needs.",
	},
	"CapSysAdmin": {
		Priority:    PriorityImmediate,
		Impact:      ImpactHost,
		ImpactScore: 98,
		Fields: []string{
			"$podSpec.containers[*].securityContext.capabilities.add",
			"$podSpec.initContainers[*].securityContext.capabilities.add",
			"$podSpec.ephemeralContainers[*].securityContext.capabilities.add",
		},
		Explanation: "CAP_SYS_ADMIN covers mount, namespace and many kernel administration operations; it is effectively root on the host.",
		Remediation: "Remove SYS_ADMIN from capabilities.add, drop ALL capabilities and add back only the minimum required capability names.",
	},
	"DockerSock": {
		Priority:    PriorityImmediate,
		Impact:      ImpactHost,
		ImpactScore: 97,
		Fields:      []string{"$podSpec.volumes[*].hostPath.path"},
		Explanation: "Mounting /var/run/docker.sock gives the container control over the node's container runtime, which commonly permits host breakout.",
		Remediation: "Remove the hostPath volume for /var/run/docker.sock; use a restricted API proxy or a dedicated runtime integration instead.",
	},
	"ProcMount": {
		Priority:    PriorityImmediate,
		Impact:      ImpactHost,
		ImpactScore: 96,
		Fields:      []string{"$podSpec.volumes[*].hostPath.path"},
		Explanation: "A host /proc mount exposes other processes and kernel state, and can provide the information needed for container escape.",
		Remediation: "Remove the hostPath volume for /proc; expose only the specific files the application requires through a projected volume.",
	},
	"HostPID": {
		Priority:    PriorityImmediate,
		Impact:      ImpactHost,
		ImpactScore: 95,
		Fields:      []string{"$podSpec.hostPID"},
		Explanation: "Sharing the host PID namespace exposes all node processes and enables process inspection or signalling beyond the pod boundary.",
		Remediation: "Set hostPID to false or remove hostPID: true from the pod spec.",
	},
	"HostIPC": {
		Priority:    PriorityImmediate,
		Impact:      ImpactHost,
		ImpactScore: 94,
		Fields:      []string{"$podSpec.hostIPC"},
		Explanation: "Sharing the host IPC namespace allows the container to read or interfere with shared memory and message queues on the node.",
		Remediation: "Set hostIPC to false or remove hostIPC: true from the pod spec.",
	},
	"HostNetwork": {
		Priority:    PriorityImmediate,
		Impact:      ImpactHost,
		ImpactScore: 93,
		Fields:      []string{"$podSpec.hostNetwork"},
		Explanation: "The host network namespace bypasses pod network isolation and can reach node-local services and loopback listeners.",
		Remediation: "Set hostNetwork to false or remove hostNetwork: true; use a Service, ingress or explicit egress path for required connectivity.",
	},
	"AllowPrivilegeEscalation": {
		Priority:    PriorityHigh,
		Impact:      ImpactContainer,
		ImpactScore: 86,
		Fields: []string{
			"$podSpec.containers[*].securityContext.allowPrivilegeEscalation",
			"$podSpec.initContainers[*].securityContext.allowPrivilegeEscalation",
			"$podSpec.ephemeralContainers[*].securityContext.allowPrivilegeEscalation",
		},
		Explanation: "Allowing privilege escalation lets a process gain capabilities such as setuid or file capabilities after the container starts, turning a limited compromise into node-level compromise.",
		Remediation: "Set securityContext.allowPrivilegeEscalation to false for every container and remove setuid binaries that are not required.",
	},
	"SecretsAsEnvironmentVariables": {
		Priority:    PriorityHigh,
		Impact:      ImpactWorkload,
		ImpactScore: 84,
		Fields: []string{
			"$podSpec.containers[*].env[*].valueFrom.secretKeyRef",
			"$podSpec.containers[*].envFrom[*].secretRef",
			"$podSpec.initContainers[*].env[*].valueFrom.secretKeyRef",
			"$podSpec.initContainers[*].envFrom[*].secretRef",
			"$podSpec.ephemeralContainers[*].env[*].valueFrom.secretKeyRef",
			"$podSpec.ephemeralContainers[*].envFrom[*].secretRef",
		},
		Explanation: "Secret values injected as environment variables are commonly copied into logs, crash dumps and child processes, increasing credential exposure.",
		Remediation: "Mount the Secret as a read-only volume and read the value from a file instead of using secretKeyRef or secretRef in env/envFrom.",
	},
	"SeccompUnconfined": {
		Priority:    PriorityHigh,
		Impact:      ImpactContainer,
		ImpactScore: 80,
		Fields: []string{
			"$podSpec.securityContext.seccompProfile.type",
			"$podSpec.containers[*].securityContext.seccompProfile.type",
			"$podSpec.initContainers[*].securityContext.seccompProfile.type",
			"$podSpec.ephemeralContainers[*].securityContext.seccompProfile.type",
		},
		Explanation: "An Unconfined seccomp profile removes the kernel syscall filter, giving a compromised container access to the full syscall surface.",
		Remediation: "Set seccompProfile.type to RuntimeDefault or a reviewed Localhost profile at pod or container level.",
	},
	"ApparmorUnconfined": {
		Priority:    PriorityHigh,
		Impact:      ImpactContainer,
		ImpactScore: 79,
		Fields: []string{
			"$podSpec.securityContext.appArmorProfile.type",
			"$podSpec.containers[*].securityContext.appArmorProfile.type",
			"$podSpec.initContainers[*].securityContext.appArmorProfile.type",
			"$podSpec.ephemeralContainers[*].securityContext.appArmorProfile.type",
		},
		Explanation: "An Unconfined AppArmor profile disables mandatory access control for the workload, allowing broader file and capability access after compromise.",
		Remediation: "Set appArmorProfile.type to RuntimeDefault or a reviewed Localhost profile at pod or container level.",
	},
	"RunAsNonRoot": {
		Priority:    PriorityHigh,
		Impact:      ImpactContainer,
		ImpactScore: 77,
		Fields: []string{
			"$podSpec.securityContext.runAsNonRoot",
			"$podSpec.containers[*].securityContext.runAsNonRoot",
			"$podSpec.initContainers[*].securityContext.runAsNonRoot",
			"$podSpec.ephemeralContainers[*].securityContext.runAsNonRoot",
		},
		Explanation: "Running as UID 0 gives the process ownership and file-permission privileges inside the container, increasing the impact of an application compromise.",
		Remediation: "Set runAsNonRoot to true at pod or container level and ensure the image declares a non-root USER.",
	},
	"AutomountServiceAccountToken": {
		Priority:    PriorityHigh,
		Impact:      ImpactCluster,
		ImpactScore: 76,
		Fields:      []string{"$podSpec.automountServiceAccountToken"},
		Explanation: "Automatically mounted service account tokens are usable credentials; a compromised pod can call the Kubernetes API with the account's permissions.",
		Remediation: "Set automountServiceAccountToken to false and mount a short-lived projected token only in workloads that need API access.",
	},
	"ServiceAccountName": {
		Priority:    PriorityHigh,
		Impact:      ImpactCluster,
		ImpactScore: 75,
		Fields:      []string{"$podSpec.serviceAccountName"},
		Explanation: "Without an explicit service account the pod uses the namespace default account, which often has more permissions than the workload needs.",
		Remediation: "Set serviceAccountName to a dedicated least-privilege service account and bind only the RBAC permissions the workload requires.",
	},
	"ReadOnlyRootFilesystem": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 70,
		Fields: []string{
			"$podSpec.containers[*].securityContext.readOnlyRootFilesystem",
			"$podSpec.initContainers[*].securityContext.readOnlyRootFilesystem",
			"$podSpec.ephemeralContainers[*].securityContext.readOnlyRootFilesystem",
		},
		Explanation: "A writable root filesystem lets an attacker persist binaries or modify application files for the lifetime of the container.",
		Remediation: "Set readOnlyRootFilesystem to true for every container and mount writable emptyDir volumes only at the paths that need writes.",
	},
	"HostAliases": {
		Priority:    PriorityMedium,
		Impact:      ImpactWorkload,
		ImpactScore: 68,
		Fields:      []string{"$podSpec.hostAliases"},
		Explanation: "Host aliases change name resolution for the pod and can redirect traffic to attacker-controlled endpoints or break service discovery.",
		Remediation: "Remove hostAliases and manage names through CoreDNS, a Service or an ExternalName resource under change control.",
	},
	"SeccompAny": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 62,
		Fields: []string{
			"$podSpec.securityContext.seccompProfile.type",
			"$podSpec.containers[*].securityContext.seccompProfile.type",
			"$podSpec.initContainers[*].securityContext.seccompProfile.type",
			"$podSpec.ephemeralContainers[*].securityContext.seccompProfile.type",
		},
		Explanation: "A seccomp profile reduces the kernel syscall surface available to a compromised process.",
		Remediation: "Set seccompProfile.type to RuntimeDefault at pod level, or to a reviewed Localhost profile for each container.",
	},
	"ApparmorAny": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 61,
		Fields: []string{
			"$podSpec.securityContext.appArmorProfile.type",
			"$podSpec.containers[*].securityContext.appArmorProfile.type",
			"$podSpec.initContainers[*].securityContext.appArmorProfile.type",
			"$podSpec.ephemeralContainers[*].securityContext.appArmorProfile.type",
		},
		Explanation: "An AppArmor profile provides mandatory access control around files, network and capabilities.",
		Remediation: "Set appArmorProfile.type to RuntimeDefault at pod level, or to a reviewed Localhost profile for each container.",
	},
	"CapDropAll": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 58,
		Fields: []string{
			"$podSpec.containers[*].securityContext.capabilities.drop",
			"$podSpec.initContainers[*].securityContext.capabilities.drop",
			"$podSpec.ephemeralContainers[*].securityContext.capabilities.drop",
		},
		Explanation: "Dropping ALL capabilities removes every Linux capability before adding back only the ones the process explicitly needs.",
		Remediation: "Set capabilities.drop to [\"ALL\"] and add only the minimum required names back under capabilities.add.",
	},
	"CapDropAny": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 56,
		Fields: []string{
			"$podSpec.containers[*].securityContext.capabilities.drop",
			"$podSpec.initContainers[*].securityContext.capabilities.drop",
			"$podSpec.ephemeralContainers[*].securityContext.capabilities.drop",
		},
		Explanation: "Dropping capabilities limits the kernel operations available to a compromised container.",
		Remediation: "Set capabilities.drop to [\"ALL\"] and add back only the specific capabilities the workload needs.",
	},
	"HostUsers": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 54,
		Fields:      []string{"$podSpec.hostUsers"},
		Explanation: "Sharing the host user namespace can expose host UID/GID mappings and weaken user-namespace isolation.",
		Remediation: "Set hostUsers to false when the cluster supports user namespaces.",
	},
	"RunAsUser": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 52,
		Fields: []string{
			"$podSpec.securityContext.runAsUser",
			"$podSpec.containers[*].securityContext.runAsUser",
			"$podSpec.initContainers[*].securityContext.runAsUser",
			"$podSpec.ephemeralContainers[*].securityContext.runAsUser",
		},
		Explanation: "A high UID avoids collisions with system users on the node and makes privilege assumptions in the image less useful.",
		Remediation: "Set runAsUser to a UID above 10000, for example 10001, at pod or container level.",
	},
	"RunAsGroup": {
		Priority:    PriorityMedium,
		Impact:      ImpactContainer,
		ImpactScore: 50,
		Fields: []string{
			"$podSpec.securityContext.runAsGroup",
			"$podSpec.containers[*].securityContext.runAsGroup",
			"$podSpec.initContainers[*].securityContext.runAsGroup",
			"$podSpec.ephemeralContainers[*].securityContext.runAsGroup",
		},
		Explanation: "A high primary group avoids collisions with system groups on the node and reduces access through shared group ownership.",
		Remediation: "Set runAsGroup to a GID above 10000, for example 10001, at pod or container level.",
	},
	"LimitsMemory": {
		Priority:    PriorityLow,
		Impact:      ImpactAvailability,
		ImpactScore: 40,
		Fields:      []string{"$podSpec.containers[*].resources.limits.memory"},
		Explanation: "A memory limit contains a runaway or malicious process and protects other workloads on the node from memory exhaustion.",
		Remediation: "Set resources.limits.memory for every container to a value derived from observed usage and load testing.",
	},
	"LimitsCPU": {
		Priority:    PriorityLow,
		Impact:      ImpactAvailability,
		ImpactScore: 38,
		Fields:      []string{"$podSpec.containers[*].resources.limits.cpu"},
		Explanation: "A CPU limit prevents one workload from consuming the node's CPU and starving co-located workloads.",
		Remediation: "Set resources.limits.cpu for every container to a value derived from observed usage and load testing.",
	},
	"RequestsMemory": {
		Priority:    PriorityLow,
		Impact:      ImpactAvailability,
		ImpactScore: 36,
		Fields:      []string{"$podSpec.containers[*].resources.requests.memory"},
		Explanation: "Memory requests let the scheduler reserve capacity and avoid placing the pod on an overcommitted node.",
		Remediation: "Set resources.requests.memory for every container, normally equal to or slightly below the memory limit.",
	},
	"RequestsCPU": {
		Priority:    PriorityLow,
		Impact:      ImpactAvailability,
		ImpactScore: 34,
		Fields:      []string{"$podSpec.containers[*].resources.requests.cpu"},
		Explanation: "CPU requests let the scheduler reserve capacity and provide a fair share under contention.",
		Remediation: "Set resources.requests.cpu for every container to a value derived from observed usage.",
	},
	"VolumeClaimRequestsStorage": {
		Priority:    PriorityLow,
		Impact:      ImpactAvailability,
		ImpactScore: 20,
		Fields:      []string{"spec.volumeClaimTemplates[*].spec.resources.requests.storage"},
		Explanation: "An explicit storage request lets the StatefulSet's PVCs bind to correctly sized persistent volumes.",
		Remediation: "Set spec.resources.requests.storage on every volumeClaimTemplate to the required capacity.",
	},
	"VolumeClaimAccessModeReadWriteOnce": {
		Priority:    PriorityLow,
		Impact:      ImpactAvailability,
		ImpactScore: 18,
		Fields:      []string{"spec.volumeClaimTemplates[*].spec.accessModes"},
		Explanation: "ReadWriteOnce matches the usual single-node access needed by a StatefulSet and avoids accidental multi-writer volumes.",
		Remediation: "Set spec.accessModes to [\"ReadWriteOnce\"] on each volumeClaimTemplate unless a different access mode is explicitly required.",
	},
}
