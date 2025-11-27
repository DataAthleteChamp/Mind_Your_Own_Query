package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Substring {
    // VULNERABLE - Tainted input flows through substring() to sink
    public static void vulnerable(String input) throws SQLException {
        String trimmed = input.substring(0, Math.min(10, input.length()));
        String query = "SELECT * FROM users WHERE name = '" + trimmed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }

    // SAFE - Substring of a literal string
    public static void safe() throws SQLException {
        String safe = "safe_value_here";
        String trimmed = safe.substring(0, 4);
        String query = "SELECT * FROM users WHERE name = '" + trimmed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}
