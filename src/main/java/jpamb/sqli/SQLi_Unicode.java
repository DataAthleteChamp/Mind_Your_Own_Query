package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Unicode {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String normalized = java.text.Normalizer.normalize(input, java.text.Normalizer.Form.NFKC);
        String query = "SELECT * FROM users WHERE name = '" + normalized + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String input = "adm\u0069n"; // "admin" with unicode
        String normalized = java.text.Normalizer.normalize(input, java.text.Normalizer.Form.NFKC);
        String query = "SELECT * FROM users WHERE name = '" + normalized + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
