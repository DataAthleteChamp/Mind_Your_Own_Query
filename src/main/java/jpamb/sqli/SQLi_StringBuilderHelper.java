package jpamb.sqli;

public class SQLi_StringBuilderHelper {
    // VULNERABLE
    public static void vulnerable(String input) {
        String query = buildQuery(input);
        executeQuery(query);
    }
    
    private static String buildQuery(String filter) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE status = ");
        sb.append(filter);
        return sb.toString();
    }
    
    // SAFE
    public static void safe() {
        String query = buildSafeQuery();
        executeQuery(query);
    }
    
    private static String buildSafeQuery() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE status = ");
        sb.append("'active'");
        return sb.toString();
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}