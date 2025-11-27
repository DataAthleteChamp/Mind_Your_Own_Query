package jpamb.sqli;

public class SQLi_NullCoalesce {
    // VULNERABLE
    public static void vulnerable(String input) {
        String value = (input != null) ? input : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String input = null;
        String value = (input != null) ? input : "admin";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}