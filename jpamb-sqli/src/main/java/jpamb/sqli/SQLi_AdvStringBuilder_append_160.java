package jpamb.sqli;

public class SQLi_AdvStringBuilder_append_160 {
    public static void vulnerable(String input) {
    StringBuilder sb = new StringBuilder();
    sb.append("SELECT * FROM users WHERE ");
    sb.append(input);
    String query = sb.toString();
        executeQuery(query);
    }
    
    public static void safe() {
    StringBuilder sb = new StringBuilder();
    sb.append("SELECT * FROM users WHERE ");
    sb.append("literal");
    String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}