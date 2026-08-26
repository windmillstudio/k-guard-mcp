package validation.kotlinfixtures

interface KotlinOwnedLookupRepository {
    fun findByOwnerAndId(ownerId: String, id: String?): Any
}

fun kotlinLookupClean(
    call: KotlinCall,
    repository: KotlinOwnedLookupRepository,
    authenticatedOwnerId: String,
): Any {
    return repository.findByOwnerAndId(
        authenticatedOwnerId,
        call.parameters["accountId"],
    )
}
