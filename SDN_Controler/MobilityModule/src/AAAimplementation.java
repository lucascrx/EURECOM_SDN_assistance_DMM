import java.util.ArrayList;
import java.util.HashMap;


public class AAAimplementation {
	
	private HashMap<Node,Prefix> prefixTable;
	private ArrayList<Long> authorizedHosts;
	
	/**Give the authorization or not to handle mobility for a given node,
	 * also provide the prefix to apply according to the provided localRouter
	 **/
	AuthenticationResponse register(long host_id, Node localRouter){
		//May be more operations to be performed
		if (this.authorizedHosts.contains(host_id)){
			//the node is authorized, we fetch router sub domain prefix
			Prefix prefix = prefixTable.get(localRouter);
			assert(prefix!=null);
			return new AuthenticationResponse(AuthenticationResponse.POSITIVE,host_id,localRouter,prefix);
		}else{
			return new AuthenticationResponse(AuthenticationResponse.NEGATIVE,(Long) null,null,null);
		}
	}

}
