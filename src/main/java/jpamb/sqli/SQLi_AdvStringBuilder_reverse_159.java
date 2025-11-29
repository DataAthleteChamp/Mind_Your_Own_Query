package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_AdvStringBuilder_reverse_159 {
    public static void vulnerable(String input) throws SQLException {
    StringBuilder sb = new StringBuilder(input);
    sb.reverse();
    sb.reverse();
    String query = "SELECT * FROM users WHERE id = " + sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
    StringBuilder sb = new StringBuilder("literal");
    sb.reverse();
    sb.reverse();
    String query = "SELECT * FROM users WHERE id = " + sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}