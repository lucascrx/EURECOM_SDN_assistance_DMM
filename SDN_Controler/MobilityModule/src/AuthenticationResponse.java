
public class AuthenticationResponse {
	

	public static int POSITIVE;
	public static int NEGATIVE;
	
	private int status;//if the mobility is granted or not
	private long hostID;//the associated host
	private Node node;//the router covering the node
	private Prefix subNetPrefix;//the prefix associated to the sub domain of the node
	
	public AuthenticationResponse(int status, long hostID, Node node, Prefix subNetPrefix) {
		this.status = status;
		this.hostID = hostID;
		this.node = node;
		this.subNetPrefix = subNetPrefix;
	}
	
	public int getStatus() {
		return this.status;
	}
	public long getHostID() {
		return hostID;
	}
	public Node getNode() {
		return node;
	}
	public Prefix getSubNetPrefix() {
		return subNetPrefix;
	}
	

}
