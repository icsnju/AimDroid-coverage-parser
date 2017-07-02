package org.javelus.minitrace.android.coverage;

import java.util.Iterator;

import org.javelus.minitrace.android.MemberMeta;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;

public class MethodData {

    MemberMeta meta;

    Method method;
    
    byte[] data;
    int insnSize;
    int covered;

    public MethodData(MemberMeta meta, Method method) {
        super();
        this.meta = meta;
        this.method = method;
        
        int total = 0;
        if (method.getImplementation() != null) {
            Iterator<? extends Instruction> it = method.getImplementation().getInstructions().iterator();
            while (it.hasNext()) {
                it.next();
                total++;
            }
        }
        
        this.insnSize = total;
        this.covered = 0;
        this.data = new byte[insnSize];
    }

    public boolean isAbstractOrNative() {
        return this.insnSize == 0;
    }

    public int getCovered() {
        return covered;
    }

    public int getInsnSize() {
        return this.insnSize;
    }

    public boolean isCovered() {
        return insnSize > 0 && covered > 0;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((meta == null) ? 0 : meta.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        MethodData other = (MethodData) obj;
        if (meta == null) {
            if (other.meta != null)
                return false;
        } else if (!meta.equals(other.meta))
            return false;
        return true;
    }

    public MemberMeta getMeta() {
        return meta;
    }

    public float getCoverage() {
        if (insnSize == 0) {
            return Float.NaN;
        }
        return covered / (float) insnSize;
    }
    
    void update() {
        int c = 0;
        for (byte b : data) {
            if (b != 0) {
                c ++;
            }
        }
        this.covered = c;
    }

    public byte[] getData() {
        return data;
    }

    public Method getMethod() {
        return method;
    }


}
