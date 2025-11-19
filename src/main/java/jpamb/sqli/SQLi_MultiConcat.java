/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_MultiConcat {
    public static void vulnerable(String string, String string2, String string3) {
        String string4 = "SELECT " + string2 + " FROM " + string + " WHERE id = " + string3;
        SQLi_MultiConcat.executeQuery(string4);
    }

    public static void safe(String string) {
        String string2 = string.replaceAll("[^0-9]", "");
        String string3 = "SELECT name FROM users WHERE id = " + string2;
        SQLi_MultiConcat.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
