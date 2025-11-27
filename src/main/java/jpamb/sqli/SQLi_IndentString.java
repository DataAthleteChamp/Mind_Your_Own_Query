package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_IndentString {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String baseQuery = "SELECT * FROM users WHERE name = '" + input + "'";
        String query = baseQuery.indent(4).stripIndent();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String baseQuery = "SELECT * FROM users WHERE id = 42";
        String query = baseQuery.indent(4).stripIndent();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
