package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_MultipleSources {
    // VULNERABLE
    public static void vulnerable(String httpInput, String fileInput) throws SQLException {
        String query = "SELECT * FROM users WHERE name = '" + httpInput + 
                       "' OR email = '" + fileInput + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String httpInput = "admin";
        String fileInput = "admin@example.com";
        String query = "SELECT * FROM users WHERE name = '" + httpInput + 
                       "' OR email = '" + fileInput + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
