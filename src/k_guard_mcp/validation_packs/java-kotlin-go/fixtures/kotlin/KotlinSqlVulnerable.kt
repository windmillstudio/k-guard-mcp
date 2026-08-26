package validation.kotlinfixtures

interface KotlinParameters {
    operator fun get(name: String): String?
}

interface KotlinCall {
    val parameters: KotlinParameters
}

interface KotlinStatement {
    fun executeQuery(query: String): Any
}

fun kotlinSqlVulnerable(call: KotlinCall, statement: KotlinStatement): Any {
    val accountId = call.parameters["accountId"]
    return statement.executeQuery("SELECT * FROM accounts WHERE id = '" + accountId + "'")
}
