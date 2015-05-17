class MobilityTracker():
    

    def __init__(self,*args,**kwargs):
        #Dictionnary : one Host ID is associated to a list of datapath ID
        self.trackingDict = {}

    
    def getTraceAndUpdate(self, newHostID, newDp):
        #Checking if new Host has a Trace or not
        if newHostID not in self.trackingDict:
            self.trackingDict[newHostID] = [newDp]
        
        trace = self.trackingDict[newHostID]
        if trace[-1].id == newDp.id:
            #the previous network is the current one OR no prior network
            return None
        # #handling the case where the node is back
        # #to a network it has already visited :
        # #the associated datapath is moved to the
        # #end of the list
        # elif newDp in trace:
        #     #other networks must have been visited before the 
        #     #come back
        #     print 'Node back in a previous network'
        #     trace.remove(newDp)
        #     trace.append(newDp)
        #     return trace
        else:
            #the host comes from a different network 
            print('Node Comes from other netwoks listed here: ')
            print(trace)
            trace.append(newDp)
            return trace        
            
