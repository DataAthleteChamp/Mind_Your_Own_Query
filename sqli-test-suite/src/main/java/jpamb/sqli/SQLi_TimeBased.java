package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_TimeBased {
    // VULNERABLE
    public static void vulnerable(String userId) throws SQLException {
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String userId = "42";
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
