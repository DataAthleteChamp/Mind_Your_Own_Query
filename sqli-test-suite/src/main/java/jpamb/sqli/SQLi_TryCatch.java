package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_TryCatch {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String query;
        try {
            query = "SELECT * FROM users WHERE id = " + input;
            Statement stmt = DatabaseHelper.getStatement();

            stmt.executeQuery(query);
        } catch (Exception e) {
            query = "SELECT * FROM default WHERE id = " + input;
            Statement stmt = DatabaseHelper.getStatement();

            stmt.executeQuery(query);
        }
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String query;
        try {
            query = "SELECT * FROM users WHERE id = 42";
            Statement stmt = DatabaseHelper.getStatement();

            stmt.executeQuery(query);
        } catch (Exception e) {
            query = "SELECT * FROM default WHERE id = 1";
            Statement stmt = DatabaseHelper.getStatement();

            stmt.executeQuery(query);
        }
    }
}
