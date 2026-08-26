package validation.javafixtures;

import javax.servlet.http.HttpServletRequest;

interface JavaLookupRepository {
    Object findById(String id);
}

final class JavaLookupVulnerable {
    Object loadAccount(HttpServletRequest request, JavaLookupRepository repository) {
        return repository.findById(request.getParameter("accountId"));
    }
}
