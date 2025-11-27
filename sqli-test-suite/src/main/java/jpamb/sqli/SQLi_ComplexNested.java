package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_ComplexNested {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String trimmed = input.trim();
        String upper = trimmed.toUpperCase();
        String[] parts = upper.split(" ");
        String first = parts.length > 0 ? parts[0] : "";
        String escaped = first.replace("'", "''");
        
        String query = "SELECT * FROM users WHERE name = '" + escaped + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String input = "  admin user  ";
        String trimmed = input.trim();
        String upper = trimmed.toUpperCase();
        String[] parts = upper.split(" ");
        String first = parts[0];
        
        String query = "SELECT * FROM users WHERE name = '" + first + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
