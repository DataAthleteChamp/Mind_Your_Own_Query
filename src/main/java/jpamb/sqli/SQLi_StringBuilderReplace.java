package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderReplace {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = 'PLACEHOLDER'");
        int start = sb.indexOf("PLACEHOLDER");
        sb.replace(start, start + "PLACEHOLDER".length(), input);
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = 'PLACEHOLDER'");
        int start = sb.indexOf("PLACEHOLDER");
        sb.replace(start, start + "PLACEHOLDER".length(), "admin");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
