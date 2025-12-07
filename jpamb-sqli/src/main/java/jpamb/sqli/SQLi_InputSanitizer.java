package jpamb.sqli;

/**
 * Test Case: Input Sanitization Pattern
 * Demonstrates incomplete vs complete input sanitization
 * 
 * New unique methods:
 * - sanitizeInput(String input)
 * - validateInput(String input)
 */
public class SQLi_InputSanitizer {
    
    // VULNERABLE - Incomplete sanitization still allows SQL injection
    public static void vulnerable(String userInput) {
        // Only removes single quotes, but SQL injection is still possible
        String sanitized = sanitizeInput(userInput);
        
        // Validation is bypassed if sanitization is incomplete
        if (!validateInput(sanitized)) {
            System.out.println("Input rejected");
            return;
        }
        
        String query = "SELECT * FROM users WHERE username = '" + sanitized + "'";
        executeQuery(query);
    }
    
    // SAFE - Uses literal value
    public static void safe() {
        String literal = "admin";
        String sanitized = sanitizeInput(literal);
        
        if (!validateInput(sanitized)) {
            System.out.println("Input rejected");
            return;
        }
        
        String query = "SELECT * FROM users WHERE username = '" + sanitized + "'";
        executeQuery(query);
    }
    
    /**
     * NEW UNIQUE METHOD #9
     * Sanitizes input by removing dangerous characters
     * NOTE: This is intentionally incomplete to demonstrate vulnerability
     */
    private static String sanitizeInput(String input) {
        // Incomplete: only removes single quotes
        // Attacker can still use: admin' OR 1=1-- becomes admin OR 1=1--
        return input.replace("'", "");
    }
    
    /**
     * NEW UNIQUE METHOD #10
     * Validates input format
     * NOTE: This validation can be bypassed with incomplete sanitization
     */
    private static boolean validateInput(String input) {
        // Check if input contains suspicious patterns
        if (input.contains("--") || input.contains(";") || input.contains("/*")) {
            return false;
        }
        // Check length
        if (input.length() > 50) {
            return false;
        }
        return true;
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
