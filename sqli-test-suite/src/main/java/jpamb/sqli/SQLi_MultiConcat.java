package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_MultiConcat {
    // VULNERABLE - Multiple tainted parameters flow to sink
    public static void vulnerable(String table, String column, String value) throws SQLException {
        String query = "SELECT " + column + " FROM " + table + " WHERE id = " + value;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }

    // SAFE - Sanitized with replaceAll removing non-digits
    public static void safe(String value) throws SQLException {
        String sanitized = value.replaceAll("[^0-9]", "");
        String query = "SELECT name FROM users WHERE id = " + sanitized;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}
