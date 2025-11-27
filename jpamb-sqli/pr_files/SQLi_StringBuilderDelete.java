package jpamb.sqli;

public class SQLi_StringBuilderDelete {
    // VULNERABLE
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE temp = 'x'");
        sb.delete(sb.indexOf("temp"), sb.indexOf("'x'"));
        sb.insert(sb.indexOf("WHERE"), "name = '" + input + "' ");
        String query = sb.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE temp = 'x'");
        sb.delete(sb.indexOf("temp"), sb.indexOf("'x'"));
        sb.insert(sb.indexOf("WHERE"), "id = 42 ");
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}