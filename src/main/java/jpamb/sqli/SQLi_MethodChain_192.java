package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_MethodChain_192 {
    public static void vulnerable(String input) throws SQLException {
        String processed = transformInput(input);
        String query = buildQuery(processed);
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String processed = transformInput("literal");
        String query = buildQuery(processed);
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    private static String transformInput(String s) {
        return s.trim().toLowerCase();
    }
    
    private static String buildQuery(String value) {
        return "SELECT * FROM users WHERE name = '" + value + "'";
    }
}