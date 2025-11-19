package jpamb.sqli;

public class SQLi_RegexReplace {
    // VULNERABLE
    public static void vulnerable(String input) {
        String cleaned = input.replaceAll("[^a-zA-Z0-9]", "_");
        String query = "SELECT * FROM users WHERE username = '" + cleaned + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String input = "admin@user!";
        String cleaned = input.replaceAll("[^a-zA-Z0-9]", "_");
        String query = "SELECT * FROM users WHERE username = '" + cleaned + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}