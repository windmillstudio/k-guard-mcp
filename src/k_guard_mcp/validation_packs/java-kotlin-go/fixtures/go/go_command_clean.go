package fixtures

import (
	"net/http"
	"os/exec"
)

func goCommandClean(request *http.Request) error {
	requested := request.FormValue("operation")
	operation := "status"
	if requested == "health" {
		operation = "health"
	}
	return exec.Command("/usr/local/bin/ops-tool", operation).Run()
}
