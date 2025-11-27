package jpamb.sqli;

public class SQLi_IndentString {
    // VULNERABLE
    public static void vulnerable(String input) {
        String baseQuery = "SELECT * FROM users WHERE name = '" + input + "'";
        String query = baseQuery.indent(4).stripIndent();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String baseQuery = "SELECT * FROM users WHERE id = 42";
        String query = baseQuery.indent(4).stripIndent();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}