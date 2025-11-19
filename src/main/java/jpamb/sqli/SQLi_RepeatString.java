package jpamb.sqli;

public class SQLi_RepeatString {
    // VULNERABLE
    public static void vulnerable(String input, int count) {
        String repeated = input.repeat(count);
        String query = "SELECT * FROM users WHERE pattern = '" + repeated + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe(int count) {
        String input = "x";
        String repeated = input.repeat(count);
        String query = "SELECT * FROM users WHERE pattern = '" + repeated + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}