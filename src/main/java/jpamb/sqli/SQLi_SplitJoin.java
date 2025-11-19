/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_SplitJoin {
    public static void vulnerable(String string) {
        String[] stringArray = string.split(",");
        String string2 = stringArray.length > 0 ? stringArray[0] : "";
        String string3 = "SELECT * FROM users WHERE id = " + string2;
        SQLi_SplitJoin.executeQuery(string3);
    }

    public static void safe() {
        String string = "42,43,44";
        String[] stringArray = string.split(",");
        String string2 = stringArray[0];
        String string3 = "SELECT * FROM users WHERE id = " + string2;
        SQLi_SplitJoin.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
