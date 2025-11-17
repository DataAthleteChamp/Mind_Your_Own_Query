package jpamb.sqli;

/**
 * Test case for classic authentication bypass via SQL injection.
 *
 * This represents one of the most common and dangerous SQL injection vulnerabilities:
 * Authentication bypass in login forms. This vulnerability allows attackers to
 * log in as any user without knowing their password.
 *
 * @category real_world
 * @difficulty medium
 * @severity critical
 */
public class SQLi_LoginBypass {

    /**
     * VULNERABLE - Classic authentication bypass vulnerability.
     *
     * Both username and password are concatenated directly into the SQL query,
     * allowing an attacker to modify the query logic.
     *
     * Attack examples:
     *   1. Username bypass:
     *      username = "admin'--"
     *      password = "anything"
     *      Result: "SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'"
     *      Impact: Comments out password check, logs in as admin
     *
     *   2. Tautology attack:
     *      username = "admin"
     *      password = "' OR '1'='1"
     *      Result: "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
     *      Impact: Always true condition, bypasses authentication
     *
     * Expected outcome: Analyzer should detect SQL injection with high confidence
     *
     * @param username Username from login form (untrusted)
     * @param password Password from login form (untrusted)
     */
    public static void vulnerable(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + username +
                       "' AND password = '" + password + "'";
        executeQuery(query);
    }

    /**
     * SAFE - Uses only literal credentials (testing/demo purposes only).
     *
     * Note: In real applications, even this should use PreparedStatement.
     * This is safe from SQL injection only because inputs are compile-time literals,
     * but it's still poor practice (hardcoded credentials, no parameterization).
     *
     * Expected outcome: Analyzer should NOT flag as vulnerable
     */
    public static void safe() {
        String username = "admin";
        String password = "secret123";
        String query = "SELECT * FROM users WHERE username = '" + username +
                       "' AND password = '" + password + "'";
        executeQuery(query);
    }

    /**
     * Helper method to simulate query execution.
     */
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}
