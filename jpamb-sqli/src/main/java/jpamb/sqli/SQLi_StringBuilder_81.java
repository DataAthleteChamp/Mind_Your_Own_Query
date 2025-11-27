package jpamb.sqli;

public class SQLi_StringBuilder_81 {
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append(input);
        sb.append("'");
        String query = sb.toString();
        executeQuery(query);
    }
    
    public static void safe() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append("admin");
        sb.append("'");
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}