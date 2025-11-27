package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderHelper {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String query = buildQuery(input);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    private static String buildQuery(String filter) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE status = ");
        sb.append(filter);
        return sb.toString();
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String query = buildSafeQuery();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    private static String buildSafeQuery() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE status = ");
        sb.append("'active'");
        return sb.toString();
    }
}
