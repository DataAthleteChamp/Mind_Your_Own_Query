package jpamb.sqli;

import java.util.StringJoiner;

public class SQLi_StringJoiner {
    // VULNERABLE
    public static void vulnerable(String[] inputs) {
        StringJoiner sj = new StringJoiner(", ", "SELECT * FROM users WHERE name IN (", ")");
        for (String input : inputs) {
            sj.add("'" + input + "'");
        }
        String query = sj.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        StringJoiner sj = new StringJoiner(", ", "SELECT * FROM users WHERE name IN (", ")");
        String[] names = {"admin", "user", "guest"};
        for (String name : names) {
            sj.add("'" + name + "'");
        }
        String query = sj.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}