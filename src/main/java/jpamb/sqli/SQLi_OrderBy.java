/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_OrderBy {
    public static void vulnerable(String string) throws SQLException {
        String string2 = "SELECT * FROM products ORDER BY " + string;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string2);
    }

    public static void safe(String string) throws SQLException {
        String string2 = string.equals("price") ? "price" : "name";
        String string3 = "SELECT * FROM products ORDER BY " + string2;
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string3);
    }
}
