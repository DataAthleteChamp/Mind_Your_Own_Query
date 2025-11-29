package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_ArrayManip_211 {
    public static void vulnerable(String[] inputs) throws SQLException {
        String[] processed = new String[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            processed[i] = inputs[i].trim();
        }
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < processed.length; i++) {
            query += "'" + processed[i] + "'";
            if (i < processed.length - 1) query += ", ";
        }
        query += ")";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
    
    public static void safe() throws SQLException {
        String[] literals = {"1", "2", "3"};
        String[] processed = new String[literals.length];
        for (int i = 0; i < literals.length; i++) {
            processed[i] = literals[i].trim();
        }
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < processed.length; i++) {
            query += "'" + processed[i] + "'";
            if (i < processed.length - 1) query += ", ";
        }
        query += ")";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}