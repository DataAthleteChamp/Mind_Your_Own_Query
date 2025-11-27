package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

import java.util.function.Function;

public class SQLi_LambdaBuilder {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        Function<String, String> queryBuilder = s -> "SELECT * FROM users WHERE name = '" + s + "'";
        String query = queryBuilder.apply(input);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        Function<String, String> queryBuilder = s -> "SELECT * FROM users WHERE name = '" + s + "'";
        String query = queryBuilder.apply("admin");
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
