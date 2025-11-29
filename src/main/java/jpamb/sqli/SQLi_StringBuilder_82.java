package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilder_82 {
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append(input);
        sb.append("'");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append("admin");
        sb.append("'");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}