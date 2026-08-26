using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

sealed class CSharpSqlClean : ControllerBase
{
    SqlCommand LoadAccount(SqlConnection connection)
    {
        string accountId = Request.Query["accountId"];
        var command = new SqlCommand("SELECT * FROM accounts WHERE id = @id", connection);
        command.Parameters.AddWithValue("@id", accountId);
        return command;
    }
}
