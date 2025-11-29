package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_WhileLoop_254 {
    public static void vulnerable(String[] inputs) throws SQLException {
        String query = "SELECT * FROM users WHERE ";
        int idx = 0;
        while (idx < inputs.length) {
            query += inputs[idx] + " OR ";
            idx++;
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String[] literals = {"admin", "user", "guest"};
        String query = "SELECT * FROM users WHERE ";
        int idx = 0;
        while (idx < literals.length) {
            query += literals[idx] + " OR ";
            idx++;
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}