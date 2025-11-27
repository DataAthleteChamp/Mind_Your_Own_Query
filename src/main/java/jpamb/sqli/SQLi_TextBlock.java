package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_TextBlock {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String query = """
            SELECT * FROM users
            WHERE name = '%s'
            """.formatted(input);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String query = """
            SELECT * FROM users
            WHERE id = %d
            """.formatted(42);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
