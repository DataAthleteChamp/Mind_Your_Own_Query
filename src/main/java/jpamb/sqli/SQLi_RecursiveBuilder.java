package jpamb.sqli;

public class SQLi_RecursiveBuilder {
    // VULNERABLE
    public static void vulnerable(String input, int depth) {
        String query = buildRecursive(input, depth);
        executeQuery(query);
    }
    
    private static String buildRecursive(String input, int depth) {
        if (depth == 0) {
            return "SELECT * FROM users WHERE name = '" + input + "'";
        }
        return buildRecursive(input, depth - 1) + " AND level = " + depth;
    }
    
    // SAFE
    public static void safe(int depth) {
        String query = buildSafeRecursive(depth);
        executeQuery(query);
    }
    
    private static String buildSafeRecursive(int depth) {
        if (depth == 0) {
            return "SELECT * FROM users WHERE id = 42";
        }
        return buildSafeRecursive(depth - 1) + " AND level = " + depth;
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}