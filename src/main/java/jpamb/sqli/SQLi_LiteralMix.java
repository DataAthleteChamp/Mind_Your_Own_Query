/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_LiteralMix {
    public static void vulnerable(String string) throws SQLException {
        String string2 = "SELECT * FROM ";
        String string3 = "users WHERE name = '" + string + "'";
        String string4 = string2 + string3;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string4);
    }

    public static void safe() throws SQLException {
        String string = "SELECT * FROM ";
        String string2 = "users WHERE id = 1";
        String string3 = string + string2;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
