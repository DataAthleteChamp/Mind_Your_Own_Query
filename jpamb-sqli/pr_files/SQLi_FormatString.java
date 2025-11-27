package jpamb.sqli;

public class SQLi_FormatString {
    // VULNERABLE
    public static void vulnerable(String input) {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", input);
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String query = String.format("SELECT * FROM users WHERE id = %d", 42);
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}