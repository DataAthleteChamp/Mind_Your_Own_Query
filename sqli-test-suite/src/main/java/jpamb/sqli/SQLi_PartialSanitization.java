package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_PartialSanitization {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String escaped = input.replace("'", "\\'");
        String query = "SELECT * FROM users WHERE name = '" + escaped + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(String input) throws SQLException {
        String sanitized = input.replaceAll("[^a-zA-Z0-9]", "");
        String query = "SELECT * FROM users WHERE name = '" + sanitized + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
