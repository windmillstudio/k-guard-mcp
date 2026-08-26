package fixtures

import (
	"net/http"

	"github.com/gorilla/mux"
)

type GoLookupStore interface {
	FindByID(string) (any, error)
}

func goLookupVulnerable(request *http.Request, store GoLookupStore) (any, error) {
	return store.FindByID(mux.Vars(request)["accountId"])
}
