package jpamb.sqli;

import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class SQLi_Encoded {
    // VULNERABLE
    public static void vulnerable(String encodedInput) {
        byte[] decoded = Base64.getDecoder().decode(encodedInput);
        String input = new String(decoded, StandardCharsets.UTF_8);
        String query = "SELECT * FROM users WHERE name = '" + input + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String literal = "admin";
        String encoded = Base64.getEncoder().encodeToString(literal.getBytes(StandardCharsets.UTF_8));
        byte[] decoded = Base64.getDecoder().decode(encoded);
        String input = new String(decoded, StandardCharsets.UTF_8);
        String query = "SELECT * FROM users WHERE name = '" + input + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}