package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_LoginBypass {
    // VULNERABLE
    public static void vulnerable(String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username +
                       "' AND password = '" + password + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }

    // SAFE
    public static void safe() throws SQLException {
        String username = "admin";
        String password = "secret123";
        String query = "SELECT * FROM users WHERE username = '" + username +
                       "' AND password = '" + password + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
