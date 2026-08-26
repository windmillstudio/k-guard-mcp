package validation.kotlinfixtures

interface KotlinLookupRepository {
    fun findById(id: String?): Any
}

fun kotlinLookupVulnerable(call: KotlinCall, repository: KotlinLookupRepository): Any {
    return repository.findById(call.parameters["accountId"])
}
