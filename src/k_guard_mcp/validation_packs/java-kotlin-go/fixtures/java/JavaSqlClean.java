package validation.javafixtures;

import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

final class JavaSqlClean {
    void loadAccount(HttpServletRequest request, Connection connection) throws Exception {
        String accountId = request.getParameter("accountId");
        PreparedStatement statement = connection.prepareStatement(
            "SELECT * FROM accounts WHERE id = ?"
        );
        statement.setString(1, accountId);
        statement.executeQuery();
    }
}
