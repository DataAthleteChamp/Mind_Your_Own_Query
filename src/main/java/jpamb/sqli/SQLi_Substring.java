/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Substring {
    public static void vulnerable(String string) throws SQLException {
        String string2 = string.substring(0, Math.min(10, string.length()));
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }

    public static void safe() throws SQLException {
        String string = "safe_value_here";
        String string2 = string.substring(0, 4);
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
