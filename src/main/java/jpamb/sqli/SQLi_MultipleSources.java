/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_MultipleSources {
    public static void vulnerable(String string, String string2) throws SQLException {
        String string3 = "SELECT * FROM users WHERE name = '" + string + "' OR email = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }

    public static void safe() throws SQLException {
        String string = "admin";
        String string2 = "admin@example.com";
        String string3 = "SELECT * FROM users WHERE name = '" + string + "' OR email = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
