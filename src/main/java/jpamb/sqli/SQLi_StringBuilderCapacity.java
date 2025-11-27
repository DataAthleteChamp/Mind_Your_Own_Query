package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderCapacity {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder(100);
        sb.append("SELECT * FROM users WHERE ");
        sb.ensureCapacity(200);
        sb.append("name = '").append(input).append("'");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder(100);
        sb.append("SELECT * FROM users WHERE ");
        sb.ensureCapacity(200);
        sb.append("id = 42");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
