/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_PartialSanitization {
    public static void vulnerable(String string) throws SQLException {
        String string2 = string.replace("'", "\\'");
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }

    public static void safe(String string) throws SQLException {
        String string2 = string.replaceAll("[^a-zA-Z0-9]", "");
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
