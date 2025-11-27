package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_EmptyString {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String filter = input.isEmpty() ? "1=1" : "name = '" + input + "'";
        String query = "SELECT * FROM users WHERE " + filter;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(String input) throws SQLException {
        String filter = input.isEmpty() ? "1=1" : "id = 42";
        String query = "SELECT * FROM users WHERE " + filter;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
