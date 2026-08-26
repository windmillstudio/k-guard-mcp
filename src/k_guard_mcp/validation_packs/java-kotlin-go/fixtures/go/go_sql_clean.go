package fixtures

import (
	"database/sql"
	"net/http"
)

func goSQLClean(request *http.Request, database *sql.DB) error {
	accountID := request.FormValue("accountId")
	statement, err := database.Prepare("SELECT * FROM accounts WHERE id = ?")
	if err != nil {
		return err
	}
	defer statement.Close()
	return statement.QueryRow(accountID).Err()
}
