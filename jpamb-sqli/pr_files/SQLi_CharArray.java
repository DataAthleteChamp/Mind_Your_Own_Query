package jpamb.sqli;

public class SQLi_CharArray {
    // VULNERABLE
    public static void vulnerable(char[] input) {
        String value = new String(input);
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        char[] input = {'a', 'd', 'm', 'i', 'n'};
        String value = new String(input);
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}