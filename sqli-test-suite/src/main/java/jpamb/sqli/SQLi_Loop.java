package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Loop {
    // VULNERABLE
    public static void vulnerable(String[] inputs) throws SQLException {
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < inputs.length; i++) {
            query += inputs[i];
            if (i < inputs.length - 1) query += ", ";
        }
        query += ")";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String query = "SELECT * FROM users WHERE id IN (";
        String[] ids = {"42", "43", "44"};
        for (int i = 0; i < ids.length; i++) {
            query += ids[i];
            if (i < ids.length - 1) query += ", ";
        }
        query += ")";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
