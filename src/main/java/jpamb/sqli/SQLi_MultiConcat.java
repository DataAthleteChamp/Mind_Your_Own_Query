/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_MultiConcat {
    public static void vulnerable(String string, String string2, String string3) throws SQLException {
        String string4 = "SELECT " + string2 + " FROM " + string + " WHERE id = " + string3;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string4);
    }

    public static void safe(String string) throws SQLException {
        String string2 = string.replaceAll("[^0-9]", "");
        String string3 = "SELECT name FROM users WHERE id = " + string2;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
