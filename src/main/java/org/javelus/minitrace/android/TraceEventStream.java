package org.javelus.minitrace.android;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class TraceEventStream implements Closeable {

    private DataInputStream in;
    private long index;

    

    public TraceEventStream(String filename) throws FileNotFoundException {
        in = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));
    }

    private int nextTwoBytes() throws IOException {
        int ch2 = in.read();
        int ch1 = in.read();
        if ((ch1 | ch2) < 0)
            throw new EOFException();
        return (char)((ch1 << 8) + (ch2 << 0));
    }
    
    private int nextFourBytes() throws IOException {
        int ch4 = in.read();
        int ch3 = in.read();
        int ch2 = in.read();
        int ch1 = in.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new EOFException();
        return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
    }
    
    public TraceEvent nextEvent(MiniTrace miniTrace) throws IOException {
        int threadId = 0;
        
        try {
            threadId = nextTwoBytes();
        } catch (EOFException e) {
            return null;
        }
        
        int tag = nextFourBytes();
        int id = tag & ~0x00000007;
        TraceEvent.EventType type = TraceEvent.EventType.valueFromTag(tag);
        
        switch (type) {
        case MethodEnter:
        case MethodExit:
        case Unroll:
            return new MethodEvent(index++, type, threadId, miniTrace.getMethod(id));
        case FieldRead:
        case FieldWrite:
            return new FieldEvent(index++, type, threadId, miniTrace.getField(id), nextFourBytes(), nextFourBytes());
        case MonitorEnter:
        case MonitorExit:
            return new MonitorEvent(index++, type, threadId, id, nextFourBytes());
        }
        
        throw new RuntimeException("Should Not Reach Here!");
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
        }
    }
}
