package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_SplitJoin {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String[] parts = input.split(",");
        String first = parts.length > 0 ? parts[0] : "";
        String query = "SELECT * FROM users WHERE id = " + first;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String value = "42,43,44";
        String[] parts = value.split(",");
        String first = parts[0];
        String query = "SELECT * FROM users WHERE id = " + first;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
