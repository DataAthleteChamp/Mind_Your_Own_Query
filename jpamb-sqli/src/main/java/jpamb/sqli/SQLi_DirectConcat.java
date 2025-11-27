/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_DirectConcat {
    public static void vulnerable(String string) {
        String string2 = "SELECT * FROM users WHERE id = " + string;
        SQLi_DirectConcat.executeQuery(string2);
    }

    public static void safe() {
        String string = "SELECT * FROM users WHERE id = 42";
        SQLi_DirectConcat.executeQuery(string);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
