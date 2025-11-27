package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Switch {
    // VULNERABLE
    public static void vulnerable(String input, int option) throws SQLException {
        String query;
        switch (option) {
            case 1:
                query = "SELECT * FROM users WHERE id = " + input;
                break;
            case 2:
                query = "SELECT * FROM admins WHERE id = " + input;
                break;
            default:
                query = "SELECT * FROM guests WHERE id = " + input;
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe(int option) throws SQLException {
        String query;
        switch (option) {
            case 1:
                query = "SELECT * FROM users WHERE id = 42";
                break;
            case 2:
                query = "SELECT * FROM admins WHERE id = 43";
                break;
            default:
                query = "SELECT * FROM guests WHERE id = 1";
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
