import java.util.ArrayList;
import java.util.HashMap;


public class MobilityTracker {
	
	private HashMap<Long,ArrayList<RouterPrefix>> trackingMap;
	
	/**Function that will return the previous domains whose the provided
	 * host registered before and update it with the new domain
	 * !!!!!!
	 * keeping all the previous domain 
	 * -> the DAAS table will have one value for 'ANCHOR LIST' field that is 
	 * completed 
	 * 
	 * QUESTION : how handle flow deletion?
	 * 
	 *QUESTION : why not having only a static table that link the Router Node to its sub-domain?
	 *why do we keep both Node & Prefix and not one of those??
	 * -> for having flexibility if we change sub domain addresses??....
	 * 
	 **/
	public ArrayList<RouterPrefix> getTraceAndUpdate(long host, Node newRouter, Prefix newPrefix){
		ArrayList<RouterPrefix> trace = new ArrayList<RouterPrefix>();
		//fetching the previous domain
		RouterPrefix oldContext = this.trackingMap.get(host).get(this.trackingMap.get(host).size()-1);
		if (oldContext != null){
			//here the new node was part of another domain before : mobility has to be handled
			RouterPrefix newContext = new RouterPrefix(newRouter,newPrefix);
			if(!newContext.equals(oldContext)){//verifying if the two domains are different
				//expanding the trace to provide : appending new context
				this.trackingMap.get(host).add(newContext);
				//forwarding it back
				trace = this.trackingMap.get(host);
			}
		}
		return trace;
	}
	


}
