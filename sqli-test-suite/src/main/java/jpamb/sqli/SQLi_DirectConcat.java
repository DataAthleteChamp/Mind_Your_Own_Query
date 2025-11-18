package jpamb.sqli;

public class SQLi_DirectConcat {
    // VULNERABLE
    public static void vulnerable(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId;
        executeQuery(query);
    }

    // SAFE
    public static void safe() {
        String query = "SELECT * FROM users WHERE id = 42";
        executeQuery(query);
    }

    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}
