__LICENSE__
package org.robovm.foo;

/*<imports>*/
/*</imports>*/

/*<javadoc>*/
/*</javadoc>*/
/*<annotations>*/
/*</annotations>*/
@Marshaler(/*<name>*/ClassName/*</name>*/.Marshaler.class)
/*<visibility>*/ public /*</visibility>*/ class /*<name>*/ClassName/*</name>*/ 
    extends /*<extends>*/Object/*</extends>*/
    /*<implements>*//*</implements>*/ {

    static { Bro.bind(/*<name>*/ClassName/*</name>*/.class); }

    /*<marshalers>*/
    /*</marshalers>*/

    /*<constants>*/
    /*</constants>*/
    
    private static /*<name>*/ClassName/*</name>*/[] values = new /*<name>*/ClassName/*</name>*/[] {/*<value_list>*//*</value_list>*/};
    
    /*<name>*/ClassName/*</name>*/ (String getterName) {
        super(Values.class, getterName);
    }
    
    public static /*<name>*/ClassName/*</name>*/ valueOf(/*<type>*/Type/*</type>*/ value) {
        for (/*<name>*/ClassName/*</name>*/ v : values) {
            if (v.value().equals(value)) {
                return v;
            }
        }
        throw new IllegalArgumentException("No constant with value " + value + " found in " 
            + /*<name>*/ClassName/*</name>*/.class.getName());
    }
    
    /*<methods>*/
    /*</methods>*/
    
    /*<annotations>*/
    /*</annotations>*/
    public static class Values {
    	static { Bro.bind(Values.class); }

        /*<values>*/
        /*</values>*/
    }
}
