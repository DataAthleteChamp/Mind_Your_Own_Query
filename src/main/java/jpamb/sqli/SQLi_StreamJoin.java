package jpamb.sqli;

import java.util.Arrays;
import java.util.stream.Collectors;

public class SQLi_StreamJoin {
    // VULNERABLE
    public static void vulnerable(String[] inputs) {
        String values = Arrays.stream(inputs)
            .map(s -> "'" + s + "'")
            .collect(Collectors.joining(", "));
        String query = "SELECT * FROM users WHERE name IN (" + values + ")";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String[] literals = {"admin", "user", "guest"};
        String values = Arrays.stream(literals)
            .map(s -> "'" + s + "'")
            .collect(Collectors.joining(", "));
        String query = "SELECT * FROM users WHERE name IN (" + values + ")";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}