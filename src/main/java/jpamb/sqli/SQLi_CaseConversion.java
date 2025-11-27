/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_CaseConversion {
    public static void vulnerable(String string) throws SQLException {
        String string2 = string.toUpperCase();
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }

    public static void safe() throws SQLException {
        String string = "admin";
        String string2 = string.toUpperCase();
        String string3 = "SELECT * FROM users WHERE role = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
