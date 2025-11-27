package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Trim {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String cleaned = input.trim();
        String query = "SELECT * FROM users WHERE id = " + cleaned;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String value = "  42  ";
        String cleaned = value.trim();
        String query = "SELECT * FROM users WHERE id = " + cleaned;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
