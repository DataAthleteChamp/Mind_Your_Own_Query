package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderReverse {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder(input);
        sb.reverse();
        String query = "SELECT * FROM users WHERE reversed_name = '" + sb.toString() + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder("nimda");
        sb.reverse(); // Results in "admin"
        String query = "SELECT * FROM users WHERE name = '" + sb.toString() + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
