package jpamb.sqli;

public class SQLi_StringBuilderChaining {
    // VULNERABLE
    public static void vulnerable(String user, String pass) {
        String query = new StringBuilder()
            .append("SELECT * FROM users WHERE username = '")
            .append(user)
            .append("' AND password = '")
            .append(pass)
            .append("'")
            .toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String query = new StringBuilder()
            .append("SELECT * FROM users WHERE username = '")
            .append("admin")
            .append("' AND password = '")
            .append("hashed_password")
            .append("'")
            .toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}