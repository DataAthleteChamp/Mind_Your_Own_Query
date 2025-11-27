package jpamb.sqli;

public class SQLi_CondAssign_235 {
    public static void vulnerable(String input, boolean useInput) {
        String value = useInput ? input : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    public static void safe(boolean useInput) {
        String value = useInput ? "literal" : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}