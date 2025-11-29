package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_IfElse_103 {
    public static void vulnerable(String input, boolean flag) throws SQLException {
        String query;
        if (flag) {
            query = "SELECT * FROM users WHERE role = '" + input + "'";
        } else {
            query = "SELECT * FROM users WHERE status = '" + input + "'";
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe(boolean flag) throws SQLException {
        String query;
        if (flag) {
            query = "SELECT * FROM users WHERE role = 'admin'";
        } else {
            query = "SELECT * FROM users WHERE status = 'active'";
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}