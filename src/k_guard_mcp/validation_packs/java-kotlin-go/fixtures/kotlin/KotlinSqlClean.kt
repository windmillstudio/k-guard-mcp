package validation.kotlinfixtures

import java.sql.Connection

fun kotlinSqlClean(call: KotlinCall, connection: Connection): Any {
    val accountId = call.parameters["accountId"]
    val statement = connection.prepareStatement("SELECT * FROM accounts WHERE id = ?")
    statement.setString(1, accountId)
    return statement.executeQuery()
}
