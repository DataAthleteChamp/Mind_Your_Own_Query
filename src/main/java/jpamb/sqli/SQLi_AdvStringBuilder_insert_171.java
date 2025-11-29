package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_AdvStringBuilder_insert_171 {
    public static void vulnerable(String input) throws SQLException {
    StringBuilder sb = new StringBuilder("SELECT * FROM users");
    sb.insert(sb.length(), " WHERE id = ");
    sb.insert(sb.length(), input);
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
    StringBuilder sb = new StringBuilder("SELECT * FROM users");
    sb.insert(sb.length(), " WHERE id = ");
    sb.insert(sb.length(), "literal");
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}