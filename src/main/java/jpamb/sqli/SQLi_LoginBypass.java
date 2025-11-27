/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_LoginBypass {
    public static void vulnerable(String string, String string2) throws SQLException {
        String string3 = "SELECT * FROM users WHERE username = '" + string + "' AND password = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }

    public static void safe() throws SQLException {
        String string = "admin";
        String string2 = "secret123";
        String string3 = "SELECT * FROM users WHERE username = '" + string + "' AND password = '" + string2 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
