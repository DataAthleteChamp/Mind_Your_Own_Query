package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Interpolation {
    // VULNERABLE
    public static void vulnerable(String table, String column, String value) throws SQLException {
        String query = "SELECT * FROM ".concat(table).concat(" WHERE ").concat(column).concat(" = '").concat(value).concat("'");
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String table = "users";
        String column = "id";
        String value = "42";
        String query = "SELECT * FROM ".concat(table).concat(" WHERE ").concat(column).concat(" = ").concat(value);
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
