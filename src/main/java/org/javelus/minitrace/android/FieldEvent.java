package org.javelus.minitrace.android;

public class FieldEvent extends TraceEvent {

    private MemberMeta field;
    private int objectId;
    private int dexPC;
    public FieldEvent(long index, EventType type, int threadId, MemberMeta field, int objectId, int dexPC) {
        super(index, type, threadId);
        this.field = field;
        this.objectId = objectId;
        this.dexPC = dexPC;
    }

    public int getObjectId() {
        return objectId;
    }

    public MemberMeta getField() {
        return field;
    }
    
    public int getDexPC() {
        return dexPC;
    }
    
    public String toString() {
        return "[" + index +"][" + threadId + "]["+ type.toString() + ", " + field + ", " + objectId + ", " + dexPC + "]"; 
    }
}
