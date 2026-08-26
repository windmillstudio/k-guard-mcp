package fixtures

import (
	"net/http"
	"os"
)

func goPathVulnerable(request *http.Request) ([]byte, error) {
	path := request.FormValue("path")
	return os.ReadFile(path)
}
