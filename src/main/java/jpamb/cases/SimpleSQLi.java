package jpamb.cases;

import jpamb.utils.Case;
import jpamb.utils.Tag;
import static jpamb.utils.Tag.TagType.*;

public class SimpleSQLi {

    private static String getParameter(String name) {
        return "1 OR 1=1";
    }

    private static void execute(String query) {
        // Simulate SQL execution
    }

    // VULNERABLE
    @Case("() -> sql injection")
    @Tag({ SQL_INJECTION })
    public static void simpleVulnerable() {
        String userId = getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;
        execute(query);
    }

    // SAFE
    @Case("() -> ok")
    @Tag({ SQL_SAFE })
    public static void simpleSafe() {
        String query = "SELECT * FROM users WHERE id = 1";
        execute(query);
    }

    // VULNERABLE
    @Case("() -> sql injection")
    @Tag({ SQL_INJECTION })
    public static void escapedButUnsafe() {
        String userName = getParameter("name");
        String escaped = userName.replace("'", "''");
        String query = "SELECT * FROM users WHERE name = '" + escaped + "'";
        execute(query);
    }
}
