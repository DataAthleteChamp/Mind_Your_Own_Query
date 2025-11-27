package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderInsert {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE 1=1");
        sb.insert(sb.length(), " AND name = '");
        sb.append(input);
        sb.append("'");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE 1=1");
        sb.insert(sb.length(), " AND name = 'admin'");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
