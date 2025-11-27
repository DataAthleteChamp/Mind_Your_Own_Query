/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_IfElse {
    public static void vulnerable(String string, boolean bl) throws SQLException {
        String string2 = bl ? "SELECT * FROM users WHERE id = " + string : "SELECT * FROM admins WHERE id = " + string;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string2);
    }

    public static void safe(boolean bl) throws SQLException {
        String string = bl ? "SELECT * FROM users WHERE id = 42" : "SELECT * FROM users WHERE id = 43";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string);
    }
}
