package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Union {
    // VULNERABLE
    public static void vulnerable(String productId) throws SQLException {
        String query = "SELECT name, price FROM products WHERE id = " + productId;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String productId = "42";
        String query = "SELECT name, price FROM products WHERE id = " + productId;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
