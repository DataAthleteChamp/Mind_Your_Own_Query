package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Loop {
    public static void vulnerable(String[] stringArray) throws SQLException {
        Object object = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < stringArray.length; ++i) {
            object = (String)object + stringArray[i];
            if (i >= stringArray.length - 1) continue;
            object = (String)object + ", ";
        }
        object = (String)object + ")";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery((String)object);
    }

    public static void safe() throws SQLException {
        Object object = "SELECT * FROM users WHERE id IN (";
        String[] stringArray = new String[]{"42", "43", "44"};
        for (int i = 0; i < stringArray.length; ++i) {
            object = (String)object + stringArray[i];
            if (i >= stringArray.length - 1) continue;
            object = (String)object + ", ";
        }
        object = (String)object + ")";
        Statement stmt = DatabaseHelper.getStatement();
        stmt.executeQuery((String)object);
    }
}
