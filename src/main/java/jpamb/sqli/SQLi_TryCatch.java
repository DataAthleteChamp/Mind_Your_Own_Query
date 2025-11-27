package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_TryCatch {
    public static void vulnerable(String string) throws SQLException {
        try {
            String string2 = "SELECT * FROM users WHERE id = " + string;
            Statement stmt = DatabaseHelper.getStatement();
            stmt.executeQuery(string2);
        }
        catch (Exception exception) {
            String string3 = "SELECT * FROM default_table WHERE id = " + string;
            Statement stmt = DatabaseHelper.getStatement();
            stmt.executeQuery(string3);
        }
    }

    public static void safe() throws SQLException {
        try {
            String query = "SELECT * FROM users WHERE id = 42";
            Statement stmt = DatabaseHelper.getStatement();
            stmt.executeQuery(query);
        }
        catch (Exception exception) {
            String query = "SELECT * FROM default_table WHERE id = 1";
            Statement stmt = DatabaseHelper.getStatement();
            stmt.executeQuery(query);
        }
    }
}
