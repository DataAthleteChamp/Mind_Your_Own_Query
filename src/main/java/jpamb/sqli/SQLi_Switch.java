package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Switch {
    public static void vulnerable(String string, int n) throws SQLException {
        String query = switch (n) {
            case 1 -> "SELECT * FROM users WHERE id = " + string;
            case 2 -> "SELECT * FROM admins WHERE id = " + string;
            default -> "SELECT * FROM guests WHERE id = " + string;
        };
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }

    public static void safe(int n) throws SQLException {
        String query = switch (n) {
            case 1 -> "SELECT * FROM users WHERE id = 42";
            case 2 -> "SELECT * FROM admins WHERE id = 43";
            default -> "SELECT * FROM guests WHERE id = 1";
        };
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}
