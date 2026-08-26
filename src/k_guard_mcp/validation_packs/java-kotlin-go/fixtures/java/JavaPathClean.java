package validation.javafixtures;

import java.nio.file.Files;
import java.nio.file.Path;
import javax.servlet.http.HttpServletRequest;

final class JavaPathClean {
    String readDocument(HttpServletRequest request) throws Exception {
        String requested = request.getParameter("document");
        Path selected = Path.of("/srv/public/help.txt");
        if ("terms".equals(requested)) {
            selected = Path.of("/srv/public/terms.txt");
        }
        return Files.readString(selected);
    }
}
