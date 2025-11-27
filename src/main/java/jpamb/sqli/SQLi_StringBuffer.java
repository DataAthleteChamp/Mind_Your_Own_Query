/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuffer {
    public static void vulnerable(String[] stringArray) throws SQLException {
        StringBuffer stringBuffer = new StringBuffer("SELECT * FROM users WHERE id IN (");
        for (String string : stringArray) {
            stringBuffer.append(string).append(", ");
        }
        stringBuffer.append(")");
        String string = stringBuffer.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string);
    }

    public static void safe() throws SQLException {
        String[] stringArray;
        StringBuffer stringBuffer = new StringBuffer("SELECT * FROM users WHERE id IN (");
        for (String string : stringArray = new String[]{"1", "2", "3"}) {
            stringBuffer.append(string).append(", ");
        }
        stringBuffer.append(")");
        String string = stringBuffer.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string);
    }
}
