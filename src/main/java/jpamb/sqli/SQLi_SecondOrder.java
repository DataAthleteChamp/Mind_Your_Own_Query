/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_SecondOrder {
    public static void vulnerable(String string) throws SQLException {
        String string2 = "INSERT INTO users (username) VALUES ('" + string + "')";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string2);
        String string3 = "SELECT * FROM logs WHERE user = '" + string + "'";
        // use existing stmt

        stmt.executeQuery(string3);
    }

    public static void safe() throws SQLException {
        String string = "admin";
        String string2 = "INSERT INTO users (username) VALUES ('" + string + "')";
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(string2);
        String string3 = "SELECT * FROM logs WHERE user = '" + string + "'";
        // use existing stmt

        stmt.executeQuery(string3);
    }
}
