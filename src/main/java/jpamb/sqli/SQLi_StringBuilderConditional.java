package jpamb.sqli;

public class SQLi_StringBuilderConditional {
    // VULNERABLE
    public static void vulnerable(String input, boolean useFilter) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users");
        if (useFilter) {
            sb.append(" WHERE name = '").append(input).append("'");
        }
        String query = sb.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe(boolean useFilter) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users");
        if (useFilter) {
            sb.append(" WHERE id = 42");
        }
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}