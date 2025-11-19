package jpamb.sqli;

public class SQLi_StringBuilderReplace {
    // VULNERABLE
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = 'PLACEHOLDER'");
        int start = sb.indexOf("PLACEHOLDER");
        sb.replace(start, start + "PLACEHOLDER".length(), input);
        String query = sb.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = 'PLACEHOLDER'");
        int start = sb.indexOf("PLACEHOLDER");
        sb.replace(start, start + "PLACEHOLDER".length(), "admin");
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}