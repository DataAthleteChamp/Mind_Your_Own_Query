/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_SecondOrder {
    public static void vulnerable(String string) {
        String string2 = "INSERT INTO users (username) VALUES ('" + string + "')";
        SQLi_SecondOrder.executeQuery(string2);
        String string3 = "SELECT * FROM logs WHERE user = '" + string + "'";
        SQLi_SecondOrder.executeQuery(string3);
    }

    public static void safe() {
        String string = "admin";
        String string2 = "INSERT INTO users (username) VALUES ('" + string + "')";
        SQLi_SecondOrder.executeQuery(string2);
        String string3 = "SELECT * FROM logs WHERE user = '" + string + "'";
        SQLi_SecondOrder.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
