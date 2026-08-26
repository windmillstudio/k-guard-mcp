package validation.javafixtures;

import javax.servlet.http.HttpServletRequest;

final class JavaCommandClean {
    Process runDiagnostic(HttpServletRequest request) throws Exception {
        String requested = request.getParameter("operation");
        String operation = "status";
        if ("health".equals(requested)) {
            operation = "health";
        }
        return new ProcessBuilder("/usr/local/bin/ops-tool", operation).start();
    }
}
