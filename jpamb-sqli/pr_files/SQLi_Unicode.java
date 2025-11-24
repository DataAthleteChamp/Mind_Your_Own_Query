package jpamb.sqli;

public class SQLi_Unicode {
    // VULNERABLE
    public static void vulnerable(String input) {
        String normalized = java.text.Normalizer.normalize(input, java.text.Normalizer.Form.NFKC);
        String query = "SELECT * FROM users WHERE name = '" + normalized + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String input = "adm\u0069n"; // "admin" with unicode
        String normalized = java.text.Normalizer.normalize(input, java.text.Normalizer.Form.NFKC);
        String query = "SELECT * FROM users WHERE name = '" + normalized + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}