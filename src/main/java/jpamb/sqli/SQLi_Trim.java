/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_Trim {
    public static void vulnerable(String string) throws SQLException {
        String string2 = string.trim();
        String string3 = "SELECT * FROM users WHERE id = " + string2;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }

    public static void safe() throws SQLException {
        String string = "  42  ";
        String string2 = string.trim();
        String string3 = "SELECT * FROM users WHERE id = " + string2;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
