package jpamb.sqli;

public class SQLi_StringBuilderSetChar {
    // VULNERABLE
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = 0");
        if (input.length() > 0) {
            sb.setCharAt(sb.length() - 1, input.charAt(0));
        }
        String query = sb.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = 0");
        sb.setCharAt(sb.length() - 1, '5');
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}