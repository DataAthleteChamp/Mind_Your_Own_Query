package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_OrderBy {
    // VULNERABLE - Tainted sortColumn flows directly to ORDER BY clause
    public static void vulnerable(String sortColumn) throws SQLException {
        String query = "SELECT * FROM products ORDER BY " + sortColumn;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }

    // SAFE - Whitelist validation, only "price" or "name" allowed
    public static void safe(String sortColumn) throws SQLException {
        String column = sortColumn.equals("price") ? "price" : "name";
        String query = "SELECT * FROM products ORDER BY " + column;
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery(query);
    }
}
