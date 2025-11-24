package jpamb.sqli;

public class SQLi_TernaryConcat {
    // VULNERABLE
    public static void vulnerable(String input, boolean isAdmin) {
        String table = isAdmin ? "admin_users" : "regular_users";
        String query = "SELECT * FROM " + table + " WHERE name = '" + input + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe(boolean isAdmin) {
        String table = isAdmin ? "admin_users" : "regular_users";
        String query = "SELECT * FROM " + table + " WHERE id = 42";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}