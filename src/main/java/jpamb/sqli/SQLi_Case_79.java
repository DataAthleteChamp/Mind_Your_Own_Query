package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Case_79 {
    public static void vulnerable(String input) throws SQLException {
        String processed = input.toLowerCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String processed = "admin".toLowerCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}