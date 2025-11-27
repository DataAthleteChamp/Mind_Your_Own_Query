package jpamb.sqli;

public class SQLi_Format_129 {
    public static void vulnerable(String input) {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", input);
        executeQuery(query);
    }
    
    public static void safe() {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", "admin");
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}