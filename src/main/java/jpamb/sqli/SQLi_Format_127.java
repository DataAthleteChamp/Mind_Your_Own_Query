package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Format_127 {
    public static void vulnerable(String input) throws SQLException {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", input);
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", "admin");
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}