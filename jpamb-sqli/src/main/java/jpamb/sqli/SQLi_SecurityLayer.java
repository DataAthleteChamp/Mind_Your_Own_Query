package jpamb.sqli;

/**
 * Test Case: Security Layer Pattern
 * Demonstrates authentication and encoding in query construction
 * 
 * New unique methods:
 * - encodeForSQL(String input)
 * - checkPermissions(String username)
 */
public class SQLi_SecurityLayer {
    
    // VULNERABLE - Encoding doesn't prevent SQL injection with untrusted input
    public static void vulnerable(String username, String action) {
        // Check permissions first
        if (!checkPermissions(username)) {
            System.out.println("Permission denied");
            return;
        }
        
        // Encode the action parameter
        String encodedAction = encodeForSQL(action);
        
        // Still vulnerable because encoding doesn't make untrusted data safe
        String query = "INSERT INTO audit_log (username, action) VALUES ('" 
                      + username + "', '" + encodedAction + "')";
        executeQuery(query);
    }
    
    // SAFE - Uses literal values
    public static void safe() {
        String username = "admin";
        String action = "VIEW_RECORDS";
        
        if (!checkPermissions(username)) {
            System.out.println("Permission denied");
            return;
        }
        
        String encodedAction = encodeForSQL(action);
        
        String query = "INSERT INTO audit_log (username, action) VALUES ('" 
                      + username + "', '" + encodedAction + "')";
        executeQuery(query);
    }
    
    /**
     * NEW UNIQUE METHOD #11
     * Encodes special characters for SQL
     * NOTE: Encoding alone doesn't prevent SQL injection
     */
    private static String encodeForSQL(String input) {
        // Simple encoding - escapes single quotes
        // This is NOT sufficient to prevent SQL injection
        return input.replace("'", "''")
                   .replace("\\", "\\\\")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r");
    }
    
    /**
     * NEW UNIQUE METHOD #12
     * Checks if user has required permissions
     * Simulates authorization check before database operation
     */
    private static boolean checkPermissions(String username) {
        // Simulate permission check
        // In real application, this would query a permissions database
        if (username == null || username.isEmpty()) {
            return false;
        }
        
        // Simulate: only admin and auditor roles have access
        return username.equals("admin") || 
               username.equals("auditor") || 
               username.startsWith("system_");
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
