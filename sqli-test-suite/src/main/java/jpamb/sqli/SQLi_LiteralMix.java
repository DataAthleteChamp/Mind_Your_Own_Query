package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_LiteralMix {
    // VULNERABLE - Tainted input flows through string concatenation to sink
    public static void vulnerable(String input) throws SQLException {
        String prefix = "SELECT * FROM ";
        String tableName = "users WHERE name = '" + input + "'";
        String query = prefix + tableName;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }

    // SAFE - Only literal strings, no tainted data
    public static void safe() throws SQLException {
        String prefix = "SELECT * FROM ";
        String tableName = "users WHERE id = 1";
        String query = prefix + tableName;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}
