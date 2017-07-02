package org.javelus.minitrace.android;

public class MonitorEvent extends TraceEvent {

    private int objectId;

    private int dexPC;

    public MonitorEvent(long index, EventType type, int threadId, int objectId, int dexPC) {
        super(index, type, threadId);
        this.objectId = objectId;
        this.dexPC = dexPC;
    }

    public int getObjectId() {
        return objectId;
    }

    public int getDexPC() {
        return dexPC;
    }

    public String toString() {
        return "[" + index +"][" + threadId + "]["+ type.toString() + ", " + objectId + ", " + dexPC + "]"; 
    }

}
