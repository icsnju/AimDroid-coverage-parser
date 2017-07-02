package org.javelus.minitrace.android.coverage;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.javelus.minitrace.android.MemberMeta;
import org.jf.dexlib2.iface.ClassDef;

public class ClassData {

    Map<MemberMeta, MethodData> methodData = new HashMap<MemberMeta, MethodData>();

    private ClassDef classDef;

    public ClassData(ClassDef classDef) {
        this.classDef = classDef;
    }

    public String getClassName() {
        return classDef.getType();
    }

    public boolean isCovered() {
        for (MethodData m : methodData.values()) {
            if (m.isCovered()) {
                return true;
            }
        }
        return false;
    }
    
    public MethodData getMethodData(MemberMeta meta) {
        return this.methodData.get(meta);
    }
    
    public void addMethodData(MethodData md) {
        this.methodData.put(md.getMeta(), md);
    }

    public Collection<MethodData> getAllMethodData() {
        return Collections.unmodifiableCollection(methodData.values());
    }
}
