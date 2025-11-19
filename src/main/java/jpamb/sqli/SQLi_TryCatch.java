/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_TryCatch {
    public static void vulnerable(String string) {
        try {
            String string2 = "SELECT * FROM users WHERE id = " + string;
            SQLi_TryCatch.executeQuery(string2);
        }
        catch (Exception exception) {
            String string3 = "SELECT * FROM default WHERE id = " + string;
            SQLi_TryCatch.executeQuery(string3);
        }
    }

    public static void safe() {
        try {
            String string = "SELECT * FROM users WHERE id = 42";
            SQLi_TryCatch.executeQuery(string);
        }
        catch (Exception exception) {
            String string = "SELECT * FROM default WHERE id = 1";
            SQLi_TryCatch.executeQuery(string);
        }
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
