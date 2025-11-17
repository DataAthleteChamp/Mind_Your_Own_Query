package jpamb.sqli;

/**
 * Test case demonstrating that substring operations preserve taint.
 *
 * Common misconception: Limiting input length with substring() makes it safe.
 * Reality: substring() does not sanitize SQL injection - it only shortens the attack.
 *
 * @category string_operations
 * @difficulty easy
 */
public class SQLi_Substring {

    /**
     * VULNERABLE - substring() operation on tainted input.
     *
     * This code attempts to limit the attack surface by restricting input length,
     * but substring() does NOT remove SQL metacharacters. The input is still tainted.
     *
     * Attack example:
     *   input = "admin' OR '1"
     *   trimmed = "admin' OR " (10 chars)
     *   Result: "SELECT * FROM users WHERE name = 'admin' OR '"
     *   Impact: Authentication bypass (partial injection still works)
     *
     * Expected outcome: Analyzer should detect SQL injection (substring preserves taint)
     *
     * @param input Untrusted user input containing potential SQL injection
     */
    public static void vulnerable(String input) {
        String trimmed = input.substring(0, Math.min(10, input.length()));
        String query = "SELECT * FROM users WHERE name = '" + trimmed + "'";
        executeQuery(query);
    }

    /**
     * SAFE - substring() operation on trusted literal.
     *
     * The source value "safe_value_here" is a string literal (trusted).
     * Taking a substring of a trusted value produces another trusted value.
     *
     * Expected outcome: Analyzer should NOT flag as vulnerable
     */
    public static void safe() {
        String safe = "safe_value_here";
        String trimmed = safe.substring(0, 4);
        String query = "SELECT * FROM users WHERE name = '" + trimmed + "'";
        executeQuery(query);
    }

    /**
     * Helper method to simulate query execution.
     */
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}
