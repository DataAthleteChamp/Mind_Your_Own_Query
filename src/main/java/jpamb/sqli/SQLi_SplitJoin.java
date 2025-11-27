/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_SplitJoin {
    public static void vulnerable(String string) throws SQLException {
        String[] stringArray = string.split(",");
        String string2 = stringArray.length > 0 ? stringArray[0] : "";
        String string3 = "SELECT * FROM users WHERE id = " + string2;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }

    public static void safe() throws SQLException {
        String string = "42,43,44";
        String[] stringArray = string.split(",");
        String string2 = stringArray[0];
        String string3 = "SELECT * FROM users WHERE id = " + string2;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
