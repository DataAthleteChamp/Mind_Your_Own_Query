package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_FormatString {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", input);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String query = String.format("SELECT * FROM users WHERE id = %d", 42);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
