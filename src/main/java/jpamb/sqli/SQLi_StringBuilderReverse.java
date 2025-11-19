package jpamb.sqli;

public class SQLi_StringBuilderReverse {
    // VULNERABLE
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder(input);
        sb.reverse();
        String query = "SELECT * FROM users WHERE reversed_name = '" + sb.toString() + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        StringBuilder sb = new StringBuilder("nimda");
        sb.reverse(); // Results in "admin"
        String query = "SELECT * FROM users WHERE name = '" + sb.toString() + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}