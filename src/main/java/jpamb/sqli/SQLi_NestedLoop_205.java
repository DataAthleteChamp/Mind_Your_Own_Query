package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_NestedLoop_205 {
    public static void vulnerable(String[][] inputs) throws SQLException {
        String query = "SELECT * FROM users WHERE ";
        for (int i = 0; i < inputs.length; i++) {
            for (int j = 0; j < inputs[i].length; j++) {
                query += inputs[i][j] + " OR ";
            }
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String[][] literals = {{"a", "b"}, {"c", "d"}};
        String query = "SELECT * FROM users WHERE ";
        for (int i = 0; i < literals.length; i++) {
            for (int j = 0; j < literals[i].length; j++) {
                query += literals[i][j] + " OR ";
            }
        }
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}