/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_Loop {
    public static void vulnerable(String[] stringArray) {
        Object object = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < stringArray.length; ++i) {
            object = (String)object + stringArray[i];
            if (i >= stringArray.length - 1) continue;
            object = (String)object + ", ";
        }
        object = (String)object + ")";
        SQLi_Loop.executeQuery((String)object);
    }

    public static void safe() {
        Object object = "SELECT * FROM users WHERE id IN (";
        String[] stringArray = new String[]{"42", "43", "44"};
        for (int i = 0; i < stringArray.length; ++i) {
            object = (String)object + stringArray[i];
            if (i >= stringArray.length - 1) continue;
            object = (String)object + ", ";
        }
        object = (String)object + ")";
        SQLi_Loop.executeQuery((String)object);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
