package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

import java.util.StringJoiner;

public class SQLi_StringJoiner {
    // VULNERABLE
    public static void vulnerable(String[] inputs) throws SQLException {
        StringJoiner sj = new StringJoiner(", ", "SELECT * FROM users WHERE name IN (", ")");
        for (String input : inputs) {
            sj.add("'" + input + "'");
        }
        String query = sj.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringJoiner sj = new StringJoiner(", ", "SELECT * FROM users WHERE name IN (", ")");
        String[] names = {"admin", "user", "guest"};
        for (String name : names) {
            sj.add("'" + name + "'");
        }
        String query = sj.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
