package validation.javafixtures;

import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

final class JavaSqlVulnerable {
    void loadAccount(HttpServletRequest request, Statement statement) throws Exception {
        String accountId = request.getParameter("accountId");
        statement.executeQuery("SELECT * FROM accounts WHERE id = '" + accountId + "'");
    }
}
