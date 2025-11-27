package jpamb.sqli;

public class SQLi_SwitchMulti_243 {
    public static void vulnerable(String input, int mode) {
        String query;
        switch (mode) {
            case 1:
                query = "SELECT * FROM users WHERE name = '" + input + "'";
                break;
            case 2:
                query = "SELECT * FROM users WHERE id = " + input;
                break;
            default:
                query = "SELECT * FROM users WHERE email = '" + input + "'";
        }
        executeQuery(query);
    }
    
    public static void safe(int mode) {
        String query;
        switch (mode) {
            case 1:
                query = "SELECT * FROM users WHERE name = 'literal'";
                break;
            case 2:
                query = "SELECT * FROM users WHERE id = 42";
                break;
            default:
                query = "SELECT * FROM users WHERE email = 'test@example.com'";
        }
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}