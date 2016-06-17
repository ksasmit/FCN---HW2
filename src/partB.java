//package org.jnetpcap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

class connection{
	long total_bytes;
	long start_time;
	long end_time;
	long init_cong_wind;
	HashMap<Long, Long> hm;
	int count=0;
    int goodput =0;
    int throughput=0;
    int RTT=0;
    int i=0,j=0;
	
}
public class partB {

    static HashSet s= new HashSet();
    //static HashMap<Long, Long> hm=new HashMap<Long,Long>();
    static HashMap<Long, connection> port_conn=new HashMap<Long,connection>();
    //static List myList = new ArrayList();
    static long src;
    static long dest;
	public static void main(String[] args) {
		
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs  
		if(args.length<1)
		{
			System.out.println("Please enter the pcap file name!!");
		}
        final String file = args[0];  
        System.out.printf("Opening file for reading: %s%n", file);  
        Pcap pcap = Pcap.openOffline(file, errbuf);
        Tcp tcp = new Tcp();
        Ip4 ip = new Ip4();
        Http http = new Http();


        Set<Integer> st= new HashSet<Integer>();
  
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
  
            public void nextPacket(PcapPacket packet, String user) {
            	
            	packetPostmartam(packet);
            	}

			private void packetPostmartam(PcapPacket packet) {
				// TODO Auto-generated method stub
				//System.out.println(packet.toString());
                    
                    
                    if (packet.hasHeader(Tcp.ID)) {  
                           
                
                        packet.getHeader(tcp);
                      //PART A
                        int wind=0;
                        long seq=0;
                        long ack=0;
                        wind=(int) (packet.getUByte(48)*Math.pow(16,2));
                        wind= wind+packet.getUByte(49);
                        
                        seq= (long) (packet.getUByte(38));
                        seq= (long) (seq* Math.pow(16,2)+ packet.getUByte(39));
                        seq= (long) (seq* Math.pow(16,2)+ packet.getUByte(40));
                        seq= (long) (seq* Math.pow(16,2)+ packet.getUByte(41));
                        
                        ack= (long) (packet.getUByte(42));
                        ack= (long) (ack* Math.pow(16,2)+ packet.getUByte(43));
                        ack= (long) (ack* Math.pow(16,2)+ packet.getUByte(44));
                        ack= (long) (ack* Math.pow(16,2)+ packet.getUByte(45));
                        
/*                        System.out.println(" seq no: "+seq);
                        System.out.println(" ack no: "+ack);
                        System.out.println(" window size : "+wind);*/
                        
                        src = tcp.getUByte(0);
    					dest = tcp.getUByte(2);
    					src = (long) (src * Math.pow(16, 2) + tcp.getUByte(1));
    					dest = (long) (dest * Math.pow(16, 2) + tcp.getUByte(3));

    					long key_port = src + dest;
    					connection connect = null;
    					if (!port_conn.containsKey(key_port)) {
    						connect = new connection();
    						connect.total_bytes+=((long) packet.size());
    						connect.hm = new HashMap<Long, Long>();
    						port_conn.put(key_port, connect);
    					} else {
    						connect = port_conn.get(key_port);
    						connect.total_bytes+=((long) packet.size());
    						//connect.end_time+= packet.getCaptureHeader().timestampInMillis();
    					}



                    	if(connect.i==0)
                    	{
                    		connect.i++;
                    		connect.start_time=packet.getCaptureHeader().timestampInMillis();
                    	}
                    	else
                    		connect.end_time=packet.getCaptureHeader().timestampInMillis();
                    	
                    	
                    	connect.hm.put(seq, packet.getCaptureHeader().timestampInMillis());
                    	if(connect.hm.containsKey(ack-1))
                    	{
                    		connect.count++;
                    		connect.RTT+=packet.getCaptureHeader().timestampInMillis()-connect.hm.get(ack-1);
                    		//myList.add(wind*8);
                    	}
                    	
                    	
                    	
                    	
                        int flags=packet.getUByte(47);
                        if((flags&0X2) == 0X2)
                        {
                        	//System.out.printf("[SYN]");
                        }
                        if((flags&0X10) == 0X10)
                        {
                        	//System.out.printf("[ACK]");
                        	if((flags&0X2) != 0X2 && (flags&0X1) != 0X1 && (flags&0X8) != 0X8 && (connect.j==0))
                        	{
                        		connect.j=1;
                        		//initial congestion window size;
                        		//connect.init_cong_wind=wind;
                        		//connect.init_cong_wind*=8;
                        		//myList.add(init_cong_win);
                        	}

                        	
                        }
                        if((flags&0X1) == 0X1)
                        {
                        	//System.out.printf("[FIN]");
                        }
                        //if(!s.contains(seq))
    					//if(!((flags&0X8) == 0X8 && (flags&0X10) == 0X10))
                        {
                        	//s.add(seq);
                        	if(packet.hasHeader(Http.ID))
                            {
                        		connect.goodput+=http.getPayloadLength();
                            }
                        	connect.goodput  += tcp.getPayloadLength();// -useful bytes
                        }
                        if (((flags & 0X2) == 0X2)) {

    						// using bytes
    						// Window size lies from byte number 48 and 49 in TCP
    						// header
                        	long l=0;
    						l= (long) packet.getUByte(56);
    						l = (long) (l * Math.pow(16, 2)
    								+ packet.getUByte(57));
    						connect.init_cong_wind  = l * 3;
    					}
                        //PART B-1
                        //connect.throughput+=packet.size();
                        //System.out.println("through put: "+throughput);
                        
                        if(packet.hasHeader(Http.ID))
                        {
                        	/*packet.getHeader(http);
                        	System.out.println("http request version:");
                        	for(int i=66;i<=74;i++)
                        		System.out.print((char)packet.getUByte(i));*/
                        		//System.out.printf("http request version::%s%n", http.fieldValue(Http.Request.RequestVersion));
                        		//System.out.printf("http response version::%s%n", http.fieldValue(Http.Response.RequestVersion));
                        }
                        //PART-B2

                    }
			}  
        };  
        try {  
            pcap.loop(-1, jpacketHandler, "Part B");

        } finally {  
        	connection connect = null;
        	Iterator it = port_conn.entrySet().iterator();
        	int i=0;
        	while (it.hasNext())
        	{
        		System.out.println("\n****************************************************************************************************\n\n");
        		System.out.println("\n\n Connection : "+(++i)+"\n\n");
        		HashMap.Entry pair = (HashMap.Entry)it.next();
        		connect= (connection) pair.getValue();
	        	System.out.println("Total size of packets: "+connect.total_bytes+" bytes");
	        	System.out.println("Total time: "+(connect.end_time-connect.start_time)+" milli-seconds");
	        	if(connect.end_time-connect.start_time !=0)
	        	{
		            System.out.println("Final throughput value: "+(1000*connect.total_bytes)/(connect.end_time-connect.start_time)+" bytes/second");
		            System.out.println("Final goodput value: "+1000*connect.goodput/(connect.end_time-connect.start_time)+" bytes/second");
		            //System.out.println("final goodput value: "+((1000*(connect.total_bytes-469))/(connect.end_time-connect.start_time)-469));
	        	}
	        	if(connect.count!=0)
	            System.out.println("Final RTT= "+(connect.RTT/connect.count)+" seconds");
	            System.out.println("Initial congestion window: "+connect.init_cong_wind+" bytes");
	            it.remove();
        	}
           pcap.close();  
        }  

	}

}
