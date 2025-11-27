package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_SecondOrder {
    // VULNERABLE
    public static void vulnerable(String username) throws SQLException {
        String insertQuery = "INSERT INTO users (username) VALUES ('" + username + "')";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(insertQuery);
        
        String selectQuery = "SELECT * FROM logs WHERE user = '" + username + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(selectQuery);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String username = "admin";
        String insertQuery = "INSERT INTO users (username) VALUES ('" + username + "')";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(insertQuery);
        
        String selectQuery = "SELECT * FROM logs WHERE user = '" + username + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(selectQuery);
    }
}
