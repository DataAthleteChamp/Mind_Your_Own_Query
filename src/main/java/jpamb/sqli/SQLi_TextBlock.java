package jpamb.sqli;

public class SQLi_TextBlock {
    // VULNERABLE
    public static void vulnerable(String input) {
        String query = """
            SELECT * FROM users
            WHERE name = '%s'
            """.formatted(input);
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String query = """
            SELECT * FROM users
            WHERE id = %d
            """.formatted(42);
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}