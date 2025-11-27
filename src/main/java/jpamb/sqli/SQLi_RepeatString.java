package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_RepeatString {
    // VULNERABLE
    public static void vulnerable(String input, int count) throws SQLException {
        String repeated = input.repeat(count);
        String query = "SELECT * FROM users WHERE pattern = '" + repeated + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(int count) throws SQLException {
        String input = "x";
        String repeated = input.repeat(count);
        String query = "SELECT * FROM users WHERE pattern = '" + repeated + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
