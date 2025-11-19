package jpamb.sqli;

public class SQLi_MultiLevelOps {
    // VULNERABLE
    public static void vulnerable(String input) {
        String step1 = input.trim();
        String step2 = step1.toLowerCase();
        String step3 = step2.replace("admin", "user");
        String[] step4 = step3.split(" ");
        String step5 = step4[0].substring(0, Math.min(5, step4[0].length()));
        String query = "SELECT * FROM users WHERE username = '" + step5 + "'";
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String step1 = "  ADMIN USER  ".trim();
        String step2 = step1.toLowerCase();
        String step3 = step2.replace("admin", "user");
        String[] step4 = step3.split(" ");
        String step5 = step4[0].substring(0, Math.min(5, step4[0].length()));
        String query = "SELECT * FROM users WHERE username = '" + step5 + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}