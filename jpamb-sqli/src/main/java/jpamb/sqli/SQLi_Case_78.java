package jpamb.sqli;

public class SQLi_Case_78 {
    public static void vulnerable(String input) {
        String processed = input.toUpperCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    public static void safe() {
        String processed = "admin".toUpperCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}