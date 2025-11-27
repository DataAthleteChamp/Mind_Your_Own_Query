/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_ComplexNested {
    public static void vulnerable(String string) throws SQLException {
        String string2 = string.trim();
        String string3 = string2.toUpperCase();
        String[] stringArray = string3.split(" ");
        String string4 = stringArray.length > 0 ? stringArray[0] : "";
        String string5 = string4.replace("'", "''");
        String string6 = "SELECT * FROM users WHERE name = '" + string5 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string6);
    }

    public static void safe() throws SQLException {
        String string = "  admin user  ";
        String string2 = string.trim();
        String string3 = string2.toUpperCase();
        String[] stringArray = string3.split(" ");
        String string4 = stringArray[0];
        String string5 = "SELECT * FROM users WHERE name = '" + string4 + "'";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string5);
    }
}
