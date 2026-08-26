using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

sealed class CSharpSqlVulnerable : ControllerBase
{
    SqlCommand LoadAccount(SqlConnection connection)
    {
        string accountId = Request.Query["accountId"];
        return new SqlCommand("SELECT * FROM accounts WHERE id = '" + accountId + "'", connection);
    }
}
