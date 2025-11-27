package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderDelete {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE temp = 'x'");
        sb.delete(sb.indexOf("temp"), sb.indexOf("'x'"));
        sb.insert(sb.indexOf("WHERE"), "name = '" + input + "' ");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE temp = 'x'");
        sb.delete(sb.indexOf("temp"), sb.indexOf("'x'"));
        sb.insert(sb.indexOf("WHERE"), "id = 42 ");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
