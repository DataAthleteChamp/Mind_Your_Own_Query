package jpamb.sqli;

public class SQLi_IfElse_108 {
    public static void vulnerable(String input, boolean flag) {
        String query;
        if (flag) {
            query = "SELECT * FROM users WHERE role = '" + input + "'";
        } else {
            query = "SELECT * FROM users WHERE status = '" + input + "'";
        }
        executeQuery(query);
    }
    
    public static void safe(boolean flag) {
        String query;
        if (flag) {
            query = "SELECT * FROM users WHERE role = 'admin'";
        } else {
            query = "SELECT * FROM users WHERE status = 'active'";
        }
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}