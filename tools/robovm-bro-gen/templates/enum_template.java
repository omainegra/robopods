__LICENSE__
package org.robovm.foo;

/*<imports>*/
/*</imports>*/

/*<javadoc>*/
/*</javadoc>*/
/*<annotations>*/
/*</annotations>*/
public enum /*<name>*/ TheName /*</name>*/ implements ValuedEnum {
    /*<values>*/
    /*</values>*/

    /*<bind>*/
    /*</bind>*/
    /*<constants>*/
    /*</constants>*/
    /*<methods>*/
    /*</methods>*/

    private final long n;

    private /*<name>*/ TheName /*</name>*/(long n) { this.n = n; }
    public long value() { return n; }
    public static /*<name>*/ TheName /*</name>*/ valueOf(long n) {
        for (/*<name>*/ TheName /*</name>*/ v : values()) {
            if (v.n == n) {
                return v;
            }
        }
        throw new IllegalArgumentException("No constant with value " + n + " found in " 
            + /*<name>*/ TheName /*</name>*/.class.getName());
    }
}
