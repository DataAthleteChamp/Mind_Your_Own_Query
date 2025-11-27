package jpamb.sqli;

public class SQLi_StringBuilderCapacity {
    // VULNERABLE
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("SELECT * FROM users WHERE ");
        sb.ensureCapacity(200);
        sb.append("name = '").append(input).append("'");
        String query = sb.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        StringBuilder sb = new StringBuilder(100);
        sb.append("SELECT * FROM users WHERE ");
        sb.ensureCapacity(200);
        sb.append("id = 42");
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}