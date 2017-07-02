package org.javelus.minitrace.android;

public class MemberMeta {

    private final String className;
    private final String name;
    private final String descriptor;

    public MemberMeta(String className, String name, String descriptor) {
        super();
        this.className = className;
        this.name = name;
        this.descriptor = descriptor;
    }

    public String getClassName() {
        return className;
    }

    public String getName() {
        return name;
    }

    public String getDescriptor() {
        return descriptor;
    }


    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((className == null) ? 0 : className.hashCode());
        result = prime * result
                + ((descriptor == null) ? 0 : descriptor.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
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
        MemberMeta other = (MemberMeta) obj;
        if (className == null) {
            if (other.className != null)
                return false;
        } else if (!className.equals(other.className))
            return false;
        if (descriptor == null) {
            if (other.descriptor != null)
                return false;
        } else if (!descriptor.equals(other.descriptor))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        return true;
    }

    public String toString() {
        return "<" + className + " " + name + " " + descriptor + ">";
    }
}
