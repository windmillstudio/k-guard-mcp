package fixtures

import "net/http"

func goSSRFClean(request *http.Request) (*http.Response, error) {
	requested := request.FormValue("service")
	endpoint := "https://status.example.test/health"
	if requested == "metrics" {
		endpoint = "https://status.example.test/metrics"
	}
	return http.Get(endpoint)
}
