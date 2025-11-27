package jpamb.sqli;

public class SQLi_Concat_33 {
    public static void vulnerable(String input) {
        String query = "SELECT * FROM users WHERE id = " + input;
        executeQuery(query);
    }
    
    public static void safe() {
        String query = "SELECT * FROM users WHERE id = 42";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}