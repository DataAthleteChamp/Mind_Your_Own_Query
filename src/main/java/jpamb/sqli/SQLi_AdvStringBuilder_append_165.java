package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_AdvStringBuilder_append_165 {
    public static void vulnerable(String input) throws SQLException {
    StringBuilder sb = new StringBuilder();
    sb.append("SELECT * FROM users WHERE ");
    sb.append(input);
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
    StringBuilder sb = new StringBuilder();
    sb.append("SELECT * FROM users WHERE ");
    sb.append("literal");
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}