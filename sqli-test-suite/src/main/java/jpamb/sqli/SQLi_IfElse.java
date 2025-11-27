package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_IfElse {
    // VULNERABLE
    public static void vulnerable(String input, boolean condition) throws SQLException {
        String query;
        if (condition) {
            query = "SELECT * FROM users WHERE id = " + input;
        } else {
            query = "SELECT * FROM admins WHERE id = " + input;
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(boolean condition) throws SQLException {
        String query;
        if (condition) {
            query = "SELECT * FROM users WHERE id = 42";
        } else {
            query = "SELECT * FROM users WHERE id = 43";
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
