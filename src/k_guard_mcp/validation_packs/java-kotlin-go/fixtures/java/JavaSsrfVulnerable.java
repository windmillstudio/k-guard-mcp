package validation.javafixtures;

import java.io.InputStream;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

final class JavaSsrfVulnerable {
    InputStream fetchPreview(HttpServletRequest request) throws Exception {
        String target = request.getParameter("target");
        return new URL(target).openStream();
    }
}
