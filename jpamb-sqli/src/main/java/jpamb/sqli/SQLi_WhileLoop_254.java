package jpamb.sqli;

public class SQLi_WhileLoop_254 {
    public static void vulnerable(String[] inputs) {
        String query = "SELECT * FROM users WHERE ";
        int idx = 0;
        while (idx < inputs.length) {
            query += inputs[idx] + " OR ";
            idx++;
        }
        executeQuery(query);
    }
    
    public static void safe() {
        String[] literals = {"admin", "user", "guest"};
        String query = "SELECT * FROM users WHERE ";
        int idx = 0;
        while (idx < literals.length) {
            query += literals[idx] + " OR ";
            idx++;
        }
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}