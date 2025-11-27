package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_VariableChain {
    // VULNERABLE
    public static void vulnerable(String input) throws SQLException {
        String query = "SELECT * FROM users";
        query = query + " WHERE ";
        query = query + "name = '";
        query = query + input;
        query = query + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String query = "SELECT * FROM users";
        query = query + " WHERE ";
        query = query + "id = ";
        query = query + "42";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
