package fixtures

import (
	"net/http"
	"os"
)

func goPathClean(request *http.Request) ([]byte, error) {
	requested := request.FormValue("document")
	selected := "/srv/public/help.txt"
	if requested == "terms" {
		selected = "/srv/public/terms.txt"
	}
	return os.ReadFile(selected)
}
