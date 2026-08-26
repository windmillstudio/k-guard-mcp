package fixtures

import (
	"net/http"
	"os/exec"
)

func goCommandVulnerable(request *http.Request) error {
	command := request.FormValue("command")
	return exec.Command("sh", "-c", command).Run()
}
