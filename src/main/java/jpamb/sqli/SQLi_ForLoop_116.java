package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_ForLoop_116 {
    public static void vulnerable(String[] inputs) throws SQLException {
        String query = "SELECT * FROM users WHERE ";
        for (int j = 0; j < inputs.length; j++) {
            query += inputs[j] + " OR ";
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String[] literals = {"admin", "user", "guest"};
        String query = "SELECT * FROM users WHERE ";
        for (int j = 0; j < literals.length; j++) {
            query += literals[j] + " OR ";
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}