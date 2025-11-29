package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Trim_64 {
    public static void vulnerable(String input) throws SQLException {
        String processed = input.trim();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String processed = "admin".trim();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}