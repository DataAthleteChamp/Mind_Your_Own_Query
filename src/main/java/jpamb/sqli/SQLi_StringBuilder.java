/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilder {
    public static void vulnerable(String string) throws SQLException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM users WHERE id = ");
        stringBuilder.append(string);
        String string2 = stringBuilder.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string2);
    }

    public static void safe() throws SQLException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM users WHERE id = ");
        stringBuilder.append("42");
        String string = stringBuilder.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string);
    }
}
