package jpamb.sqli;

import java.util.function.Function;

public class SQLi_LambdaBuilder {
    // VULNERABLE
    public static void vulnerable(String input) {
        Function<String, String> queryBuilder = s -> "SELECT * FROM users WHERE name = '" + s + "'";
        String query = queryBuilder.apply(input);
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        Function<String, String> queryBuilder = s -> "SELECT * FROM users WHERE name = '" + s + "'";
        String query = queryBuilder.apply("admin");
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}