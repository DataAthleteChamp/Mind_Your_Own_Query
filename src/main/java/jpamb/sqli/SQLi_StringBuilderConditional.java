package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderConditional {
    // VULNERABLE
    public static void vulnerable(String input, boolean useFilter) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users");
        if (useFilter) {
            sb.append(" WHERE name = '").append(input).append("'");
        }
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(boolean useFilter) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users");
        if (useFilter) {
            sb.append(" WHERE id = 42");
        }
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
