package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_CaseConversion {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String upper = input.toUpperCase();
        String query = "SELECT * FROM users WHERE name = '" + upper + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String value = "admin";
        String upper = value.toUpperCase();
        String query = "SELECT * FROM users WHERE role = '" + upper + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
