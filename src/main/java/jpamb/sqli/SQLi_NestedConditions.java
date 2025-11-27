package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_NestedConditions {
    public static void vulnerable(String string, boolean bl, boolean bl2) throws SQLException {
        Object object = "SELECT * FROM users WHERE ";
        object = bl ? (bl2 ? (String)object + "id = " + string : (String)object + "name = '" + string + "'") : (String)object + "email = '" + string + "'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery((String)object);
    }

    public static void safe(boolean bl, boolean bl2) throws SQLException {
        Object object = "SELECT * FROM users WHERE ";
        object = bl ? (bl2 ? (String)object + "id = 42" : (String)object + "name = 'admin'") : (String)object + "email = 'test@example.com'";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery((String)object);
    }
}
