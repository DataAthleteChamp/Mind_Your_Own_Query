package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_NestedConditions {
    // VULNERABLE
    public static void vulnerable(String input, boolean a, boolean b) throws SQLException {
        String query = "SELECT * FROM users WHERE ";
        if (a) {
            if (b) {
                query += "id = " + input;
            } else {
                query += "name = '" + input + "'";
            }
        } else {
            query += "email = '" + input + "'";
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(boolean a, boolean b) throws SQLException {
        String query = "SELECT * FROM users WHERE ";
        if (a) {
            if (b) {
                query += "id = 42";
            } else {
                query += "name = 'admin'";
            }
        } else {
            query += "email = 'test@example.com'";
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
