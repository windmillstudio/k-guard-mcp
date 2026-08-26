package validation.javafixtures;

import javax.servlet.http.HttpServletRequest;

interface JavaOwnedLookupRepository {
    Object findByOwnerAndId(String ownerId, String id);
}

final class JavaLookupClean {
    Object loadAccount(
        HttpServletRequest request,
        JavaOwnedLookupRepository repository,
        String authenticatedOwnerId
    ) {
        return repository.findByOwnerAndId(
            authenticatedOwnerId,
            request.getParameter("accountId")
        );
    }
}
