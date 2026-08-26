package validation.javafixtures;

import javax.servlet.http.HttpServletRequest;

final class JavaCommandVulnerable {
    Process runDiagnostic(HttpServletRequest request) throws Exception {
        String command = request.getParameter("command");
        return Runtime.getRuntime().exec(command);
    }
}
