package fixtures

import "net/http"

func goSSRFVulnerable(request *http.Request) (*http.Response, error) {
	target := request.FormValue("target")
	return http.Get(target)
}
