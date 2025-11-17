package jpamb.cases;

import jpamb.utils.Case;
import jpamb.utils.Tag;
import static jpamb.utils.Tag.TagType.*;

/**
 * Simplified SQL injection test cases for taint analysis.
 *
 * These demonstrate SQL injection patterns using string operations
 * without requiring external dependencies like HttpServletRequest.
 *
 * Note: These are simplified demonstrations. Real SQL injection detection
 * would require handling actual HTTP request parameters and SQL connections.
 */
public class SimpleSQLi {

    /**
     * Simulates HttpServletRequest.getParameter()
     * This is a source of untrusted data.
     */
    private static String getParameter(String name) {
        return "1 OR 1=1";
    }

    /**
     * Simulates Statement.execute()
     * This is a SQL execution sink.
     */
    private static void execute(String query) {
        // Simulate SQL execution
    }

    /**
     * Test Case 1: Simple vulnerable - direct concatenation
     *
     * Vulnerable: Simulated user input directly concatenated into SQL query.
     * Expected: sql injection
     */
    @Case("() -> sql injection")
    @Tag({ SQL_INJECTION })
    public static void simpleVulnerable() {
        String userId = getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;
        execute(query);
    }

    /**
     * Test Case 2: Simple safe - all literals
     *
     * Safe: Query uses only string literals, no user input.
     * Expected: ok
     */
    @Case("() -> ok")
    @Tag({ SQL_SAFE })
    public static void simpleSafe() {
        String query = "SELECT * FROM users WHERE id = 1";
        execute(query);
    }

    /**
     * Test Case 3: Escaped but unsafe
     *
     * Vulnerable: Even with escaping, tainted data in query is unsafe.
     * Variable-level taint tracking should detect this.
     * Expected: sql injection
     */
    @Case("() -> sql injection")
    @Tag({ SQL_INJECTION })
    public static void escapedButUnsafe() {
        String userName = getParameter("name");
        String escaped = userName.replace("'", "''");
        String query = "SELECT * FROM users WHERE name = '" + escaped + "'";
        execute(query);
    }
}
