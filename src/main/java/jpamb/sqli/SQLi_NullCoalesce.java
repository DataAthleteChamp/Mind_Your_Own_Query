package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_NullCoalesce {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String value = (input != null) ? input : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String input = null;
        String value = (input != null) ? input : "admin";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
