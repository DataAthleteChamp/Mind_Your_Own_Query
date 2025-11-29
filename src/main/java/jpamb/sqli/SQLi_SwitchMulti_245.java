package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_SwitchMulti_245 {
    public static void vulnerable(String input, int mode) throws SQLException {
        String query;
        switch (mode) {
            case 1:
                query = "SELECT * FROM users WHERE name = '" + input + "'";
                break;
            case 2:
                query = "SELECT * FROM users WHERE id = " + input;
                break;
            default:
                query = "SELECT * FROM users WHERE email = '" + input + "'";
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe(int mode) throws SQLException {
        String query;
        switch (mode) {
            case 1:
                query = "SELECT * FROM users WHERE name = 'literal'";
                break;
            case 2:
                query = "SELECT * FROM users WHERE id = 42";
                break;
            default:
                query = "SELECT * FROM users WHERE email = 'test@example.com'";
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}