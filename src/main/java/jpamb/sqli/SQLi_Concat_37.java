package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Concat_37 {
    public static void vulnerable(String input) throws SQLException {
        String query = "SELECT * FROM users WHERE id = " + input;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String query = "SELECT * FROM users WHERE id = 42";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}