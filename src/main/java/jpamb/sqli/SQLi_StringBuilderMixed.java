/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderMixed {
    public static void vulnerable(String string) throws SQLException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM ");
        stringBuilder.append("users");
        stringBuilder.append(" WHERE name = '");
        stringBuilder.append(string);
        stringBuilder.append("'");
        String string2 = stringBuilder.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string2);
    }

    public static void safe() throws SQLException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM ");
        stringBuilder.append("users");
        stringBuilder.append(" WHERE id = ");
        stringBuilder.append("42");
        String string = stringBuilder.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string);
    }
}
