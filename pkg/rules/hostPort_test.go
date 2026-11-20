package rules

import (
	"testing"

	"sigs.k8s.io/yaml"
)

func Test_HostPort_Pod(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: hostport-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - containerPort: 80
      hostPort: 8080
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_Pod_No_HostPort(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: no-hostport-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - containerPort: 80
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 0 {
		t.Errorf("Got %v containers wanted %v", containers, 0)
	}
}

func Test_HostPort_Pod_Multiple_Containers_One_HostPort(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: multi-container-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - containerPort: 80
      hostPort: 8080
  - name: c2
    image: redis
    ports:
    - containerPort: 6379
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_Pod_Multiple_Containers_All_HostPort(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: multi-hostport-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - containerPort: 80
      hostPort: 8080
  - name: c2
    image: redis
    ports:
    - containerPort: 6379
      hostPort: 16379
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 2 {
		t.Errorf("Got %v containers wanted %v", containers, 2)
	}
}

func Test_HostPort_Pod_Multiple_Ports_One_Container(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: multi-port-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - containerPort: 80
      hostPort: 8080
    - containerPort: 443
      hostPort: 8443
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_Pod_ContainerPort_Only(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: containerport-only-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - containerPort: 80
    - containerPort: 443
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 0 {
		t.Errorf("Got %v containers wanted %v", containers, 0)
	}
}

func Test_HostPort_Pod_HostPort_Zero(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: hostport-zero-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - containerPort: 80
      hostPort: 0
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 0 {
		t.Errorf("Got %v containers wanted %v", containers, 0)
	}
}

func Test_HostPort_Pod_InitContainer(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: init-hostport-pod
spec:
  initContainers:
  - name: init1
    image: busybox
    ports:
    - containerPort: 9000
      hostPort: 9000
  containers:
  - name: c1
    image: nginx
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_Pod_EphemeralContainer(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: ephemeral-hostport-pod
spec:
  containers:
  - name: c1
    image: nginx
  ephemeralContainers:
  - name: debugger
    image: busybox
    ports:
    - containerPort: 9999
      hostPort: 9999
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_Pod_No_Ports(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: no-ports-pod
spec:
  containers:
  - name: c1
    image: nginx
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 0 {
		t.Errorf("Got %v containers wanted %v", containers, 0)
	}
}

func Test_HostPort_Deployment(t *testing.T) {
	var data = `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hostport-deployment
spec:
  template:
    spec:
      containers:
      - name: c1
        image: nginx
        ports:
        - containerPort: 80
          hostPort: 8080
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_Deployment_No_HostPort(t *testing.T) {
	var data = `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-hostport-deployment
spec:
  template:
    spec:
      containers:
      - name: c1
        image: nginx
        ports:
        - containerPort: 80
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 0 {
		t.Errorf("Got %v containers wanted %v", containers, 0)
	}
}

func Test_HostPort_StatefulSet(t *testing.T) {
	var data = `
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: hostport-statefulset
spec:
  template:
    spec:
      containers:
      - name: c1
        image: nginx
        ports:
        - containerPort: 80
          hostPort: 8080
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_DaemonSet(t *testing.T) {
	var data = `
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: hostport-daemonset
spec:
  template:
    spec:
      containers:
      - name: c1
        image: fluentd
        ports:
        - containerPort: 24224
          hostPort: 24224
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_CronJob(t *testing.T) {
	var data = `
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hostport-cronjob
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: c1
            image: busybox
            ports:
            - containerPort: 8080
              hostPort: 8080
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}

func Test_HostPort_CronJob_No_HostPort(t *testing.T) {
	var data = `
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: no-hostport-cronjob
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: c1
            image: busybox
            ports:
            - containerPort: 8080
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 0 {
		t.Errorf("Got %v containers wanted %v", containers, 0)
	}
}

func Test_HostPort_Deployment_InitContainer_And_Container(t *testing.T) {
	var data = `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mixed-hostport-deployment
spec:
  template:
    spec:
      initContainers:
      - name: init1
        image: busybox
        ports:
        - containerPort: 9000
          hostPort: 9000
      containers:
      - name: c1
        image: nginx
        ports:
        - containerPort: 80
          hostPort: 8080
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 2 {
		t.Errorf("Got %v containers wanted %v", containers, 2)
	}
}

func Test_HostPort_Pod_Empty_Ports(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: empty-ports-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports: []
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 0 {
		t.Errorf("Got %v containers wanted %v", containers, 0)
	}
}

func Test_HostPort_Deployment_Three_Containers_Two_HostPort(t *testing.T) {
	var data = `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: three-container-deployment
spec:
  template:
    spec:
      containers:
      - name: c1
        image: nginx
        ports:
        - containerPort: 80
          hostPort: 8080
      - name: c2
        image: redis
        ports:
        - containerPort: 6379
      - name: c3
        image: memcached
        ports:
        - containerPort: 11211
          hostPort: 11211
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 2 {
		t.Errorf("Got %v containers wanted %v", containers, 2)
	}
}

func Test_HostPort_Pod_HostPort_And_ContainerPort(t *testing.T) {
	var data = `
---
apiVersion: v1
kind: Pod
metadata:
  name: hostport-and-containerport-pod
spec:
  containers:
  - name: c1
    image: nginx
    ports:
    - name: http
      containerPort: 80
      hostPort: 80
      protocol: TCP
`

	json, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		t.Fatal(err.Error())
	}

	containers := HostPort(json)
	if containers != 1 {
		t.Errorf("Got %v containers wanted %v", containers, 1)
	}
}
