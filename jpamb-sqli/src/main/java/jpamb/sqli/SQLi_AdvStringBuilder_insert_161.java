package jpamb.sqli;

public class SQLi_AdvStringBuilder_insert_161 {
    public static void vulnerable(String input) {
    StringBuilder sb = new StringBuilder("SELECT * FROM users");
    sb.insert(sb.length(), " WHERE id = ");
    sb.insert(sb.length(), input);
    String query = sb.toString();
        executeQuery(query);
    }
    
    public static void safe() {
    StringBuilder sb = new StringBuilder("SELECT * FROM users");
    sb.insert(sb.length(), " WHERE id = ");
    sb.insert(sb.length(), "literal");
    String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}