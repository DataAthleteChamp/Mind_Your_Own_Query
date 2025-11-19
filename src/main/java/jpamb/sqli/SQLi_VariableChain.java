package jpamb.sqli;

public class SQLi_VariableChain {
    // VULNERABLE
    public static void vulnerable(String input) {
        String query = "SELECT * FROM users";
        query = query + " WHERE ";
        query = query + "name = '";
        query = query + input;
        query = query + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String query = "SELECT * FROM users";
        query = query + " WHERE ";
        query = query + "id = ";
        query = query + "42";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}