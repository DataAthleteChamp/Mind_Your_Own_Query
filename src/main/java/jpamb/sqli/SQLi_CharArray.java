package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_CharArray {
    // VULNERABLE
    public static void vulnerable(char[] input) throws SQLException {
        String value = new String(input);
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        char[] input = {'a', 'd', 'm', 'i', 'n'};
        String value = new String(input);
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
