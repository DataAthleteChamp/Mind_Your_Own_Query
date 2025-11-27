package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_RegexReplace {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String cleaned = input.replaceAll("[^a-zA-Z0-9]", "_");
        String query = "SELECT * FROM users WHERE username = '" + cleaned + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String input = "admin@user!";
        String cleaned = input.replaceAll("[^a-zA-Z0-9]", "_");
        String query = "SELECT * FROM users WHERE username = '" + cleaned + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
