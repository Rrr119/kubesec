package rules

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/thedevsaddam/gojsonq/v2"
)

func HostPort(json []byte) int {
	spec := getSpecSelector(json)
	jq := gojsonq.New().Reader(bytes.NewReader(json))
	found := 0

	containerPaths := []string{
		spec + ".containers",
		spec + ".initContainers",
		spec + ".ephemeralContainers",
	}

	for _, containerPath := range containerPaths {
		containerCount := jq.Copy().From(containerPath).Count()

		for i := 0; i < containerCount; i++ {
			containerNode := fmt.Sprintf("%s.[%s]", containerPath, strconv.Itoa(i))
			portsNode := containerNode + ".ports"
			portsCount := jq.Copy().From(portsNode).Count()

			for j := 0; j < portsCount; j++ {
				hostPort := jq.Copy().From(fmt.Sprintf("%s.[%s].hostPort", portsNode, strconv.Itoa(j))).Get()
				if hostPort != nil {
					if port, ok := hostPort.(float64); ok && port > 0 {
						found++
						break
					}
				}
			}
		}
	}

	return found
}
