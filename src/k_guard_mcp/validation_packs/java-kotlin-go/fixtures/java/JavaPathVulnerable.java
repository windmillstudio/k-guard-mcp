package validation.javafixtures;

import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

final class JavaPathVulnerable {
    FileInputStream openDocument(HttpServletRequest request) throws Exception {
        String path = request.getParameter("path");
        return new FileInputStream(path);
    }
}
