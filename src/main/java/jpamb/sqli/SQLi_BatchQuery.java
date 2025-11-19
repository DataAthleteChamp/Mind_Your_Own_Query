package jpamb.sqli;

public class SQLi_BatchQuery {
    // VULNERABLE
    public static void vulnerable(String[] inputs) {
        String queries = "";
        for (int i = 0; i < inputs.length; i++) {
            queries += "SELECT * FROM users WHERE id = " + inputs[i] + "; ";
        }
        executeQuery(queries);
    }
    
    // SAFE
    public static void safe() {
        String queries = "";
        String[] ids = {"1", "2", "3"};
        for (int i = 0; i < ids.length; i++) {
            queries += "SELECT * FROM users WHERE id = " + ids[i] + "; ";
        }
        executeQuery(queries);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}