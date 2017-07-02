package org.javelus.minitrace.android;

public class MethodEvent extends TraceEvent {

    private MemberMeta method;
    
    public MethodEvent(long index, EventType type, int threadId, MemberMeta method) {
        super(index, type, threadId);
        this.method = method;
    }

    public MemberMeta getMethod () {
        return method;
    }
    
    public String toString() {
        return "[" + index +"][" + threadId + "]["+ type.toString() + ", " + method  + "]"; 
    }
}
