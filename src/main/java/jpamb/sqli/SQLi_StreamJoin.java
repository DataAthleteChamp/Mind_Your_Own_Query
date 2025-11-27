package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

import java.util.Arrays;
import java.util.stream.Collectors;

public class SQLi_StreamJoin {
    // VULNERABLE
    public static void vulnerable(String[] inputs) throws SQLException {
        String values = Arrays.stream(inputs)
            .map(s -> "'" + s + "'")
            .collect(Collectors.joining(", "));
        String query = "SELECT * FROM users WHERE name IN (" + values + ")";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String[] literals = {"admin", "user", "guest"};
        String values = Arrays.stream(literals)
            .map(s -> "'" + s + "'")
            .collect(Collectors.joining(", "));
        String query = "SELECT * FROM users WHERE name IN (" + values + ")";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
