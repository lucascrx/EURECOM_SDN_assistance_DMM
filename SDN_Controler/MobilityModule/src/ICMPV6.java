import java.util.ArrayList;
import java.util.HashMap;


public class ICMPV6 extends Packet {
	
	public static int TYPE_ROUTER_SOLLICITATION;
	
	public static String MN_IDENTIFIER;
	
	
	private int type;
	private HashMap<String,Long> parameters;
	

	public int getType() {
		return type;
	}
	
	public long getParamValue(String paramName){
		return this.parameters.get(paramName);
	}
	
	
}
