package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuffer {
    // VULNERABLE
    public static void vulnerable(String[] inputs) throws SQLException {
        StringBuffer sb = new StringBuffer("SELECT * FROM users WHERE id IN (");
        for (String input : inputs) {
            sb.append(input).append(", ");
        }
        sb.append(")");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuffer sb = new StringBuffer("SELECT * FROM users WHERE id IN (");
        String[] ids = {"1", "2", "3"};
        for (String id : ids) {
            sb.append(id).append(", ");
        }
        sb.append(")");
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
