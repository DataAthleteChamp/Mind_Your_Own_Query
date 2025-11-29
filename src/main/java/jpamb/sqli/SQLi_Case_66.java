package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Case_66 {
    public static void vulnerable(String input) throws SQLException {
        String processed = input.toUpperCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String processed = "admin".toUpperCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}