package jpamb.sqli;

public class SQLi_MethodChain_190 {
    public static void vulnerable(String input) {
        String processed = transformInput(input);
        String query = buildQuery(processed);
        executeQuery(query);
    }
    
    public static void safe() {
        String processed = transformInput("literal");
        String query = buildQuery(processed);
        executeQuery(query);
    }
    
    private static String transformInput(String s) {
        return s.trim().toLowerCase();
    }
    
    private static String buildQuery(String value) {
        return "SELECT * FROM users WHERE name = '" + value + "'";
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}