	/**Private Class to have a clearer Tracking HashMap**/
	public class RouterPrefix{
		private Node router;
		private Prefix prefix;
		
		
		
		public RouterPrefix(Node rout,Prefix pref){
			this.router = rout;
			this.prefix = pref;
		}
		
		
		public Node getRouter(){
			return this.router;
		}
		
		public Prefix getPrefix(){
			return this.prefix;
		}
		
	}