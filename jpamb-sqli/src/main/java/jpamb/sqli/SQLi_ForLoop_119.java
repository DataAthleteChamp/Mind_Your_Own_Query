package jpamb.sqli;

public class SQLi_ForLoop_119 {
    public static void vulnerable(String[] inputs) {
        String query = "SELECT * FROM users WHERE ";
        for (int j = 0; j < inputs.length; j++) {
            query += inputs[j] + " OR ";
        }
        executeQuery(query);
    }
    
    public static void safe() {
        String[] literals = {"admin", "user", "guest"};
        String query = "SELECT * FROM users WHERE ";
        for (int j = 0; j < literals.length; j++) {
            query += literals[j] + " OR ";
        }
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}