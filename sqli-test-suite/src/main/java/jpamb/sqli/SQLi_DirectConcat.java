package jpamb.sqli;

/**
 * Test case for basic SQL injection via direct string concatenation.
 *
 * This is the simplest and most common SQL injection pattern where
 * user input is directly concatenated into a SQL query string.
 *
 * @category basic_concatenation
 * @difficulty easy
 */
public class SQLi_DirectConcat {

    /**
     * VULNERABLE - Direct concatenation of untrusted input into SQL query.
     *
     * Attack example:
     *   userId = "1 OR 1=1--"
     *   Result: "SELECT * FROM users WHERE id = 1 OR 1=1--"
     *   Impact: Returns all users instead of just user with id=1
     *
     * Expected outcome: Analyzer should detect SQL injection with high confidence
     *
     * @param userId Untrusted user input (e.g., from HTTP request parameter)
     */
    public static void vulnerable(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId;
        executeQuery(query);
    }

    /**
     * SAFE - Uses only literal values, no user input.
     *
     * This query is safe because it contains no untrusted data.
     * All values are hardcoded literals known at compile time.
     *
     * Expected outcome: Analyzer should NOT flag as vulnerable
     */
    public static void safe() {
        String query = "SELECT * FROM users WHERE id = 42";
        executeQuery(query);
    }

    /**
     * Helper method to simulate query execution.
     * In real code, this would execute the SQL query against a database.
     */
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}
