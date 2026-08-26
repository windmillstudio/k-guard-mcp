package fixtures

import (
	"database/sql"
	"net/http"
)

func goSQLVulnerable(request *http.Request, database *sql.DB) error {
	accountID := request.FormValue("accountId")
	_, err := database.Query("SELECT * FROM accounts WHERE id = '" + accountID + "'")
	return err
}
