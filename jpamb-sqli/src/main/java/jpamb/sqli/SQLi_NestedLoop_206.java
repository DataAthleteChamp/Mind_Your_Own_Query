package jpamb.sqli;

public class SQLi_NestedLoop_206 {
    public static void vulnerable(String[][] inputs) {
        String query = "SELECT * FROM users WHERE ";
        for (int i = 0; i < inputs.length; i++) {
            for (int j = 0; j < inputs[i].length; j++) {
                query += inputs[i][j] + " OR ";
            }
        }
        executeQuery(query);
    }
    
    public static void safe() {
        String[][] literals = {{"a", "b"}, {"c", "d"}};
        String query = "SELECT * FROM users WHERE ";
        for (int i = 0; i < literals.length; i++) {
            for (int j = 0; j < literals[i].length; j++) {
                query += literals[i][j] + " OR ";
            }
        }
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}