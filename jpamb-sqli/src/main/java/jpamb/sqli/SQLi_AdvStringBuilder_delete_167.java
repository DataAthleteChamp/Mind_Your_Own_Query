package jpamb.sqli;

public class SQLi_AdvStringBuilder_delete_167 {
    public static void vulnerable(String input) {
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = " + input);
    sb.delete(0, 0);
    String query = sb.toString();
        executeQuery(query);
    }
    
    public static void safe() {
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = " + "literal");
    sb.delete(0, 0);
    String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}