package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_BatchQuery {
    // VULNERABLE
    public static void vulnerable(String[] inputs) throws SQLException {
        String queries = "";
        for (int i = 0; i < inputs.length; i++) {
            queries += "SELECT * FROM users WHERE id = " + inputs[i] + "; ";
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(queries);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String queries = "";
        String[] ids = {"1", "2", "3"};
        for (int i = 0; i < ids.length; i++) {
            queries += "SELECT * FROM users WHERE id = " + ids[i] + "; ";
        }
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(queries);
    }
}
