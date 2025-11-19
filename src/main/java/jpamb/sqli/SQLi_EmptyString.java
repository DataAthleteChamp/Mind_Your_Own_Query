package jpamb.sqli;

public class SQLi_EmptyString {
    // VULNERABLE
    public static void vulnerable(String input) {
        String filter = input.isEmpty() ? "1=1" : "name = '" + input + "'";
        String query = "SELECT * FROM users WHERE " + filter;
        executeQuery(query);
    }
    
    // SAFE
    public static void safe(String input) {
        String filter = input.isEmpty() ? "1=1" : "id = 42";
        String query = "SELECT * FROM users WHERE " + filter;
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}