package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_RecursiveBuilder {
    // VULNERABLE
    public static void vulnerable(String input, int depth) throws SQLException {
        String query = buildRecursive(input, depth);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    private static String buildRecursive(String input, int depth) {
        if (depth == 0) {
            return "SELECT * FROM users WHERE name = '" + input + "'";
        }
        return buildRecursive(input, depth - 1) + " AND level = " + depth;
    }
    
    // SAFE
    public static void safe(int depth) throws SQLException {
        String query = buildSafeRecursive(depth);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    private static String buildSafeRecursive(int depth) {
        if (depth == 0) {
            return "SELECT * FROM users WHERE id = 42";
        }
        return buildSafeRecursive(depth - 1) + " AND level = " + depth;
    }
}
