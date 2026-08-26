package validation.javafixtures;

import java.io.InputStream;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

final class JavaSsrfClean {
    InputStream fetchStatus(HttpServletRequest request) throws Exception {
        String requested = request.getParameter("service");
        String endpoint = "https://status.example.test/health";
        if ("metrics".equals(requested)) {
            endpoint = "https://status.example.test/metrics";
        }
        return new URL(endpoint).openStream();
    }
}
