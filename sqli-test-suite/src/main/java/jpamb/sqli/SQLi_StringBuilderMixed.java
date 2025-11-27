package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderMixed {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM ");
        sb.append("users");
        sb.append(" WHERE name = '");
        sb.append(input);
        sb.append("'");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM ");
        sb.append("users");
        sb.append(" WHERE id = ");
        sb.append("42");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
