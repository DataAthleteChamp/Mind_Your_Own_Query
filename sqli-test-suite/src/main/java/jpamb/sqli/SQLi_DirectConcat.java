package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_DirectConcat {
    // VULNERABLE - Tainted userId flows to Statement.executeQuery()
    public static void vulnerable(String userId) throws SQLException {
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);  // SINK: java.sql.Statement.executeQuery
    }

    // SAFE - No tainted data, only literals
    public static void safe() throws SQLException {
        String query = "SELECT * FROM users WHERE id = 42";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);  // SINK: java.sql.Statement.executeQuery
    }
}
