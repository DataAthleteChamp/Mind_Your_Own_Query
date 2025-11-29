package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_AdvStringBuilder_delete_167 {
    public static void vulnerable(String input) throws SQLException {
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = " + input);
    sb.delete(0, 0);
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = " + "literal");
    sb.delete(0, 0);
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}