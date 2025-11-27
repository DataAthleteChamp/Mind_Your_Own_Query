package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Replace {
    // VULNERABLE - Quote escaping is insufficient (taint preserved through replace)
    public static void vulnerable(String input) throws SQLException {
        String escaped = input.replace("'", "''");
        String query = "SELECT * FROM users WHERE name = '" + escaped + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }

    // SAFE - Replace on literal strings only
    public static void safe() throws SQLException {
        String base = "SELECT * FROM table_name WHERE x = y";
        String query = base.replace("table_name", "users");
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}
