package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_AdvStringBuilder_replace_163 {
    public static void vulnerable(String input) throws SQLException {
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE placeholder");
    sb.replace(sb.indexOf("placeholder"), sb.length(), input);
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE placeholder");
    sb.replace(sb.indexOf("placeholder"), sb.length(), "literal");
    String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}