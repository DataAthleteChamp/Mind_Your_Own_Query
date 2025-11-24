package jpamb.sqli;

public class SQLi_AdvStringBuilder_reverse_169 {
    public static void vulnerable(String input) {
    StringBuilder sb = new StringBuilder(input);
    sb.reverse();
    sb.reverse();
    String query = "SELECT * FROM users WHERE id = " + sb.toString();
        executeQuery(query);
    }
    
    public static void safe() {
    StringBuilder sb = new StringBuilder("literal");
    sb.reverse();
    sb.reverse();
    String query = "SELECT * FROM users WHERE id = " + sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}