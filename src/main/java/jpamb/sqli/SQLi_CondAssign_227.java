package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_CondAssign_227 {
    public static void vulnerable(String input, boolean useInput) throws SQLException {
        String value = useInput ? input : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe(boolean useInput) throws SQLException {
        String value = useInput ? "literal" : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}