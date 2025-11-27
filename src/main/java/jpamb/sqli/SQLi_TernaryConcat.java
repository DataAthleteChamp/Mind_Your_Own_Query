package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_TernaryConcat {
    // VULNERABLE
    public static void vulnerable(String input, boolean isAdmin) throws SQLException {
        String table = isAdmin ? "admin_users" : "regular_users";
        String query = "SELECT * FROM " + table + " WHERE name = '" + input + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(boolean isAdmin) throws SQLException {
        String table = isAdmin ? "admin_users" : "regular_users";
        String query = "SELECT * FROM " + table + " WHERE id = 42";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
