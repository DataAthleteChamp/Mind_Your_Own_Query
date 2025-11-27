package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderSetChar {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = 0");
        if (input.length() > 0) {
            sb.setCharAt(sb.length() - 1, input.charAt(0));
        }
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = 0");
        sb.setCharAt(sb.length() - 1, '5');
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
