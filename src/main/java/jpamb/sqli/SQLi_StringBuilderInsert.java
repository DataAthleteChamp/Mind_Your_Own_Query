package jpamb.sqli;

public class SQLi_StringBuilderInsert {
    // VULNERABLE
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE 1=1");
        sb.insert(sb.length(), " AND name = '");
        sb.append(input);
        sb.append("'");
        String query = sb.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE 1=1");
        sb.insert(sb.length(), " AND name = 'admin'");
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}