/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_NestedConditions {
    public static void vulnerable(String string, boolean bl, boolean bl2) {
        Object object = "SELECT * FROM users WHERE ";
        object = bl ? (bl2 ? (String)object + "id = " + string : (String)object + "name = '" + string + "'") : (String)object + "email = '" + string + "'";
        SQLi_NestedConditions.executeQuery((String)object);
    }

    public static void safe(boolean bl, boolean bl2) {
        Object object = "SELECT * FROM users WHERE ";
        object = bl ? (bl2 ? (String)object + "id = 42" : (String)object + "name = 'admin'") : (String)object + "email = 'test@example.com'";
        SQLi_NestedConditions.executeQuery((String)object);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
