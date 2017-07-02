package org.javelus.minitrace.android;

public abstract class TraceEvent {
    
    /**
     * kMiniTraceMethodEnter = 0x00,       // method entry
     * kMiniTraceMethodExit = 0x01,        // method exit
     * kMiniTraceUnroll = 0x02,            // method exited by exception unrolling
     * kMiniTraceFieldRead = 0x03,         // field read
     * kMiniTraceFieldWrite = 0x04,        // field write
     * kMiniTraceMonitorEnter = 0x05,      // monitor enter
     * kMiniTraceMonitorExit = 0x06,       // monitor exit
     * kMiniTraceActionMask = 0x07,        // three bits
     * @author t
     *
     */
    enum EventType {
        MethodEnter(0, 6),
        MethodExit(1, 6),
        Unroll(2, 6),
        FieldRead(3, 14),
        FieldWrite(4, 14),
        MonitorEnter(5, 10),
        MonitorExit(6, 10);
        
        public int bitValue;
        public int recordLength;
        
        EventType(int bitValue, int recordLength) {
            this.bitValue = bitValue;
            this.recordLength = recordLength;
        }
        
        public static EventType valueFromTag(int tag) {
            return valueOf(tag & 0x00000007);
        }
        
        public static EventType valueOf(int value) {
            switch (value) {
            case 0:
                return MethodEnter;
            case 1:
                return MethodExit;
            case 2:
                return Unroll;
            case 3:
                return FieldRead;
            case 4:
                return FieldWrite;
            case 5:
                return MonitorEnter;
            case 6:
                return MonitorExit;
            }
            throw new RuntimeException("Should not reach here!");
        }
    }
    
    protected final long index;
    protected final EventType type;
    protected int threadId;
    public TraceEvent(long index, EventType type, int threadId) {
        this.index = index;
        this.type = type;
        this.threadId = threadId;
    }
    
    public int getThreadId() {
        return threadId;
    }
    
    public long getIndex() {
        return index;
    }
    
    public EventType getType() {
        return type;
    }
}
