package jpamb.sqli;

public class SQLi_Case_69 {
    public static void vulnerable(String input) {
        String processed = input.toLowerCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    public static void safe() {
        String processed = "admin".toLowerCase();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}